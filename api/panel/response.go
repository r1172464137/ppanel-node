package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-resty/resty/v2"
)

type responseEnvelope struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func checkHTTPResponse(r *resty.Response, url string) error {
	if r == nil {
		return fmt.Errorf("服务端返回为空")
	}
	if r.StatusCode() >= http.StatusBadRequest {
		if isProtobufResponse(r) {
			result, err := unmarshalProtobufResult(r.Body())
			if err != nil {
				return fmt.Errorf("访问 %s 失败: HTTP %d: %w", url, r.StatusCode(), err)
			}
			return fmt.Errorf("访问 %s 失败: HTTP %d code=%d msg=%s", url, r.StatusCode(), result.Code, result.Message)
		}
		return fmt.Errorf("访问 %s 失败: %s", url, string(r.Body()))
	}
	return nil
}

func checkPanelEnvelope(code int, msg, url string) error {
	if code == 0 || code == http.StatusOK {
		return nil
	}
	if strings.TrimSpace(msg) == "" {
		msg = "面板返回错误"
	}
	return fmt.Errorf("访问 %s 失败: code=%d msg=%s", url, code, msg)
}

func checkPanelResponse(r *resty.Response, url string) error {
	if isProtobufResponse(r) {
		result, err := unmarshalProtobufResult(r.Body())
		if err != nil {
			return err
		}
		if err := checkHTTPResponse(r, url); err != nil {
			return err
		}
		return checkPanelEnvelope(int(result.Code), result.Message, url)
	}
	if err := checkHTTPResponse(r, url); err != nil {
		return err
	}
	body := r.Body()
	if len(body) == 0 {
		return nil
	}
	var resp responseEnvelope
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("解码响应体失败: %w", err)
	}
	return checkPanelEnvelope(resp.Code, resp.Msg, url)
}
