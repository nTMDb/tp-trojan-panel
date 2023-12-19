package dto

type NodePageDto struct {
	NodeDto
	BaseDto
}

type NodeDto struct {
	Name         *string `json:"name" form:"name" validate:"omitempty,min=0,max=20"`
	NodeServerId *uint   `json:"nodeServerId" form:"nodeServerId" validate:"omitempty,gte=0"`
}

type NodeCreateDto struct {
	NodeServerId *uint   `json:"nodeServerId" form:"nodeServerId" validate:"required,gt=0"`
	NodeTypeId   *uint   `json:"nodeTypeId" form:"nodeTypeId" validate:"required,gt=0"`
	Name         *string `json:"name" form:"name" validate:"required,min=2,max=20"`
	Domain       *string `json:"domain" form:"domain" validate:"required,ip|fqdn,min=4,max=64"`
	Port         *uint   `json:"port" form:"port" validate:"required,validatePort"`
	Priority     *int    `json:"priority" form:"priority" validate:"required,validateInt"`

	XrayProtocol       *string `json:"xrayProtocol" form:"xrayProtocol" validate:"omitempty,min=0,max=32"`
	XrayFlow           *string `json:"xrayFlow" form:"xrayFlow" validate:"omitempty,min=0,max=32"`
	XraySSMethod       *string `json:"xraySSMethod" form:"xraySSMethod" validate:"omitempty,min=0,max=32"`
	RealityPbk         *string `json:"realityPbk" form:"realityPbk" validate:"omitempty,min=0,max=64"`
	XraySettings       *string `json:"xraySettings" form:"xraySettings" validate:"omitempty,min=0,max=1024"`
	XrayStreamSettings *string `json:"xrayStreamSettings" form:"xrayStreamSettings" validate:"omitempty,min=0,max=1024"`
	XrayTag            *string `json:"xrayTag" form:"xrayTag" validate:"omitempty,min=0,max=64"`
	XraySniffing       *string `json:"xraySniffing" form:"xraySniffing" validate:"omitempty,min=0,max=256"`
	XrayAllocate       *string `json:"xrayAllocate" form:"xrayAllocate" validate:"omitempty,min=0,max=256"`

	TrojanGoSni             *string `json:"trojanGoSni" form:"trojanGoSni" validate:"omitempty,min=0,max=64"`
	TrojanGoMuxEnable       *uint   `json:"trojanGoMuxEnable" form:"trojanGoMuxEnable" validate:"required,oneof=0 1"`
	TrojanGoWebsocketEnable *uint   `json:"trojanGoWebsocketEnable" form:"trojanGoWebsocketEnable" validate:"required,oneof=0 1"`
	TrojanGoWebsocketPath   *string `json:"trojanGoWebsocketPath" form:"trojanGoWebsocketPath" validate:"omitempty,min=0,max=64"`
	TrojanGoWebsocketHost   *string `json:"trojanGoWebsocketHost" form:"trojanGoWebsocketHost" validate:"omitempty,min=0,max=64"`
	TrojanGoSsEnable        *uint   `json:"trojanGoSsEnable" form:"trojanGoSsEnable" validate:"required,oneof=0 1"`
	TrojanGoSsMethod        *string `json:"trojanGoSsMethod" form:"trojanGoSsMethod" validate:"omitempty,min=0,max=32"`
	TrojanGoSsPassword      *string `json:"trojanGoSsPassword" form:"trojanGoSsPassword" validate:"omitempty,min=0,max=64"`

	HysteriaProtocol   *string `json:"hysteriaProtocol" form:"hysteriaProtocol" validate:"omitempty,min=0,max=32"`
	HysteriaObfs       *string `json:"hysteriaObfs" form:"hysteriaObfs" validate:"omitempty,min=0,max=64"`
	HysteriaUpMbps     *int    `json:"hysteriaUpMbps" form:"hysteriaUpMbps" validate:"required,gt=0,lte=9999999999"`
	HysteriaDownMbps   *int    `json:"hysteriaDownMbps" form:"hysteriaDownMbps" validate:"required,gt=0,lte=9999999999"`
	HysteriaServerName *string `json:"hysteriaServerName" form:"hysteriaServerName" validate:"omitempty,min=0,max=64"`
	HysteriaInsecure   *uint   `json:"hysteriaInsecure" form:"hysteriaInsecure" validate:"omitempty,oneof=0 1"`
	HysteriaFastOpen   *uint   `json:"hysteriaFastOpen" form:"hysteriaFastOpen" validate:"omitempty,oneof=0 1"`

	Hysteria2ObfsPassword *string `json:"hysteria2ObfsPassword" form:"hysteria2ObfsPassword" validate:"omitempty,validateObfsPassword"`
	Hysteria2UpMbps       *int    `json:"hysteria2UpMbps" form:"hysteria2UpMbps" validate:"required,gt=0,lte=9999999999"`
	Hysteria2DownMbps     *int    `json:"hysteria2DownMbps" form:"hysteria2DownMbps" validate:"required,gt=0,lte=9999999999"`
	Hysteria2ServerName   *string `json:"hysteria2ServerName" form:"hysteria2ServerName" validate:"omitempty,min=0,max=64"`
	Hysteria2Insecure     *uint   `json:"hysteria2Insecure" form:"hysteria2Insecure" validate:"omitempty,oneof=0 1"`
}

type NodeUpdateDto struct {
	RequiredIdDto
	NodeServerId *uint   `json:"nodeServerId" form:"nodeServerId" validate:"required,gt=0"`
	NodeSubId    *uint   `json:"nodeSubId" form:"nodeSubId" validate:"required,gte=0"`
	NodeTypeId   *uint   `json:"nodeTypeId" form:"nodeTypeId" validate:"required,gt=0"`
	Name         *string `json:"name" form:"name" validate:"required,min=2,max=20"`
	Domain       *string `json:"domain" form:"domain" validate:"required,ip|fqdn,min=4,max=64"`
	Port         *uint   `json:"port" form:"port" validate:"required,validatePort"`
	Priority     *int    `json:"priority" form:"priority" validate:"required,validateInt"`

	XrayProtocol       *string `json:"xrayProtocol" form:"xrayProtocol" validate:"omitempty,min=0,max=32"`
	XrayFlow           *string `json:"xrayFlow" form:"xrayFlow" validate:"omitempty,min=0,max=32"`
	XraySSMethod       *string `json:"xraySSMethod" form:"xraySSMethod" validate:"omitempty,min=0,max=32"`
	RealityPbk         *string `json:"realityPbk" form:"realityPbk" validate:"omitempty,min=0,max=64"`
	XraySettings       *string `json:"xraySettings" form:"xraySettings" validate:"omitempty,min=0,max=1024"`
	XrayStreamSettings *string `json:"xrayStreamSettings" form:"xrayStreamSettings" validate:"omitempty,min=0,max=1024"`
	XrayTag            *string `json:"xrayTag" form:"xrayTag" validate:"omitempty,min=0,max=64"`
	XraySniffing       *string `json:"xraySniffing" form:"xraySniffing" validate:"omitempty,min=0,max=256"`
	XrayAllocate       *string `json:"xrayAllocate" form:"xrayAllocate" validate:"omitempty,min=0,max=256"`

	TrojanGoSni             *string `json:"trojanGoSni" form:"trojanGoSni" validate:"omitempty,min=0,max=64"`
	TrojanGoMuxEnable       *uint   `json:"trojanGoMuxEnable" form:"trojanGoMuxEnable" validate:"required,oneof=0 1"`
	TrojanGoWebsocketEnable *uint   `json:"trojanGoWebsocketEnable" form:"trojanGoWebsocketEnable" validate:"required,oneof=0 1"`
	TrojanGoWebsocketPath   *string `json:"trojanGoWebsocketPath" form:"trojanGoWebsocketPath" validate:"omitempty,min=0,max=64"`
	TrojanGoWebsocketHost   *string `json:"trojanGoWebsocketHost" form:"trojanGoWebsocketHost" validate:"omitempty,min=0,max=64"`
	TrojanGoSsEnable        *uint   `json:"trojanGoSsEnable" form:"trojanGoSsEnable" validate:"required,oneof=0 1"`
	TrojanGoSsMethod        *string `json:"trojanGoSsMethod" form:"trojanGoSsMethod" validate:"omitempty,min=0,max=32"`
	TrojanGoSsPassword      *string `json:"trojanGoSsPassword" form:"trojanGoSsPassword" validate:"omitempty,min=0,max=64"`

	HysteriaProtocol   *string `json:"hysteriaProtocol" form:"hysteriaProtocol" validate:"omitempty,min=0,max=32"`
	HysteriaObfs       *string `json:"hysteriaObfs" form:"hysteriaObfs" validate:"omitempty,min=0,max=64"`
	HysteriaUpMbps     *int    `json:"hysteriaUpMbps" form:"hysteriaUpMbps" validate:"required,gt=0,lte=9999999999"`
	HysteriaDownMbps   *int    `json:"hysteriaDownMbps" form:"hysteriaDownMbps" validate:"required,gt=0,lte=9999999999"`
	HysteriaServerName *string `json:"hysteriaServerName" form:"hysteriaServerName" validate:"omitempty,min=0,max=64"`
	HysteriaInsecure   *uint   `json:"hysteriaInsecure" form:"hysteriaInsecure" validate:"omitempty,oneof=0 1"`
	HysteriaFastOpen   *uint   `json:"hysteriaFastOpen" form:"hysteriaFastOpen" validate:"omitempty,oneof=0 1"`

	Hysteria2ObfsPassword *string `json:"hysteria2ObfsPassword" form:"hysteria2ObfsPassword" validate:"omitempty,validateObfsPassword"`
	Hysteria2UpMbps       *int    `json:"hysteria2UpMbps" form:"hysteria2UpMbps" validate:"required,gt=0,lte=9999999999"`
	Hysteria2DownMbps     *int    `json:"hysteria2DownMbps" form:"hysteria2DownMbps" validate:"required,gt=0,lte=9999999999"`
	Hysteria2ServerName   *string `json:"hysteria2ServerName" form:"hysteria2ServerName" validate:"omitempty,min=0,max=64"`
	Hysteria2Insecure     *uint   `json:"hysteria2Insecure" form:"hysteria2Insecure" validate:"omitempty,oneof=0 1"`
}

type NodeUrlDto struct {
	Id         *uint   `json:"id" form:"id" validate:"required"`
	ClientType *string `json:"clientType" form:"clientType" validate:"required"`
}
