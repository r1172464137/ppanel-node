package panel

import (
	"context"
	"fmt"
	"path"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users"`
}

type UserOnlineBody struct {
	Users []OnlineUser `json:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// Users are delivered in the candidate identity snapshot; the separate
// user list endpoint is gone.

func (c *NodeClient) GetUserAlive() (map[int]int, error) {
	c.AliveMap = &AliveMap{}
	c.AliveMap.Alive = make(map[int]int)
	/*const path = "/v1/server/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err != nil || r.StatusCode() >= 399 {
		c.AliveMap.Alive = make(map[int]int)
	}
	if r == nil || r.RawResponse == nil {
		fmt.Printf("received nil response or raw response")
		c.AliveMap.Alive = make(map[int]int)
	}
	defer r.RawResponse.Body.Close()
	if err := json.Unmarshal(r.Body(), c.AliveMap); err != nil {
		//fmt.Printf("unmarshal user alive list error: %s", err)
		c.AliveMap.Alive = make(map[int]int)
	}
	*/
	return c.AliveMap.Alive, nil
}

type ServerPushUserTrafficRequest struct {
	Traffic []UserTraffic `json:"traffic"`
}

type UserTraffic struct {
	UID      int   `json:"uid"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

func (c *NodeClient) ReportUserTraffic(ctx context.Context, userTraffic *[]UserTraffic) error {
	if c.UseProtobuf {
		return c.reportUserTrafficProtobuf(ctx, userTraffic)
	}
	traffic := make([]UserTraffic, 0)
	for _, t := range *userTraffic {
		traffic = append(traffic, UserTraffic{
			UID:      t.UID,
			Upload:   t.Upload,
			Download: t.Download,
		})
	}
	p := "/v1/server/push"
	req := ServerPushUserTrafficRequest{
		Traffic: traffic,
	}
	r, err := c.Client.R().
		SetContext(ctx).
		SetBody(req).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), redactTransportError(err))
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}

func (c *NodeClient) reportUserTrafficProtobuf(ctx context.Context, userTraffic *[]UserTraffic) error {
	const p = "/v1/server/push"
	traffic := make([]*serverv1.UserTraffic, 0, len(*userTraffic))
	for _, item := range *userTraffic {
		traffic = append(traffic, &serverv1.UserTraffic{
			UserId:   int64(item.UID),
			Upload:   item.Upload,
			Download: item.Download,
		})
	}
	request := c.Client.R().SetContext(ctx)
	if err := setProtobufRequestBody(request, &serverv1.PushUserTrafficRequest{Traffic: traffic}); err != nil {
		return err
	}
	r, err := request.Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), redactTransportError(err))
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}

func (c *NodeClient) ReportNodeOnlineUsers(ctx context.Context, data *[]OnlineUser) error {
	if c.UseProtobuf {
		return c.reportNodeOnlineUsersProtobuf(ctx, data)
	}
	const p = "/v1/server/online"
	users := UserOnlineBody{
		Users: *data,
	}
	r, err := c.Client.R().
		SetContext(ctx).
		SetBody(users).
		ForceContentType("application/json").
		Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), redactTransportError(err))
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}

func (c *NodeClient) reportNodeOnlineUsersProtobuf(ctx context.Context, data *[]OnlineUser) error {
	const p = "/v1/server/online"
	users := make([]*serverv1.OnlineUser, 0, len(*data))
	for _, item := range *data {
		users = append(users, &serverv1.OnlineUser{UserId: int64(item.UID), Ip: item.IP})
	}
	request := c.Client.R().SetContext(ctx)
	if err := setProtobufRequestBody(request, &serverv1.PushOnlineUsersRequest{Users: users}); err != nil {
		return err
	}
	r, err := request.Post(p)
	if err != nil {
		return fmt.Errorf("访问 %s 失败: %s", path.Join(c.APIHost+p), redactTransportError(err))
	}
	return checkPanelResponse(r, path.Join(c.APIHost+p))
}
