package bo

import "time"

type NodeBo struct {
	Id                 uint      `json:"id"`
	NodeServerId       uint      `json:"nodeServerId"`
	NodeSubId          uint      `json:"nodeSubId"`
	NodeTypeId         uint      `json:"nodeTypeId"`
	Name               string    `json:"name"`
	NodeServerIp       string    `json:"nodeServerIp"`
	NodeServerGrpcPort uint      `json:"nodeServerGrpcPort"`
	Domain             string    `json:"domain"`
	Port               uint      `json:"port"`
	Priority           int       `json:"priority"`
	CreateTime         time.Time `json:"createTime"`

	Status int `json:"status"`
}

type V2rayNVmess struct {
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	Id   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	Tls  string `json:"tls"`
	Sni  string `json:"sni"`
	Alpn string `json:"alpn"`
	Fp   string `json:"'fp'"`
}
