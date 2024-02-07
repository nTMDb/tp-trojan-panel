package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"trojan-panel/dao"
	"trojan-panel/model"
	"trojan-panel/model/bo"
	"trojan-panel/model/constant"
	"trojan-panel/util"
)

// NodeURLShadowrocket Shadowrocket分享链接
func NodeURLShadowrocket(node *model.Node, nodeType *model.NodeType, username string, password string) (string, error) {
	// 构建URL
	var headBuilder strings.Builder

	if *nodeType.Id == constant.Xray {
		nodeXray, err := dao.SelectNodeXrayById(node.NodeSubId)
		if err != nil {
			return "", errors.New(constant.NodeURLError)
		}
		streamSettings := bo.StreamSettings{}
		if nodeXray.StreamSettings != nil && *nodeXray.StreamSettings != "" {
			if err := json.Unmarshal([]byte(*nodeXray.StreamSettings), &streamSettings); err != nil {
				return "", errors.New(constant.NodeURLError)
			}
		}
		settings := bo.Settings{}
		if nodeXray.Settings != nil && *nodeXray.Settings != "" {
			if err := json.Unmarshal([]byte(*nodeXray.Settings), &settings); err != nil {
				return "", errors.New(constant.NodeURLError)
			}
		}

		connectPass := password

		if *nodeXray.Protocol == constant.ProtocolVless ||
			*nodeXray.Protocol == constant.ProtocolVmess ||
			*nodeXray.Protocol == constant.ProtocolTrojan {
			if *nodeXray.Protocol == constant.ProtocolVless || *nodeXray.Protocol == constant.ProtocolVmess {
				connectPass = util.GenerateUUID(password)
			}
			headBuilder.WriteString(fmt.Sprintf("%s://%s@%s:%d?type=%s&security=%s",
				*nodeXray.Protocol,
				url.PathEscape(connectPass),
				*node.Domain,
				*node.Port,
				streamSettings.Network,
				streamSettings.Security))
			if *nodeXray.Protocol == constant.ProtocolVmess {
				headBuilder.WriteString("&alterId=0")
				if settings.Encryption == "none" {
					headBuilder.WriteString("&encryption=none")
				}
			}
			if nodeXray.Protocol != nil && *nodeXray.Protocol != "" {
				headBuilder.WriteString(fmt.Sprintf("&flow=%s", *nodeXray.XrayFlow))
			}

			if streamSettings.Security == "tls" {
				headBuilder.WriteString(fmt.Sprintf("&sni=%s", streamSettings.TlsSettings.ServerName))
				headBuilder.WriteString(fmt.Sprintf("&fp=%s", streamSettings.TlsSettings.Fingerprint))
				if len(streamSettings.TlsSettings.Alpn) > 0 {
					alpns := strings.Replace(strings.Trim(fmt.Sprint(streamSettings.TlsSettings.Alpn), "[]"), " ", ",", -1)
					headBuilder.WriteString(fmt.Sprintf("&alpn=%s", url.PathEscape(alpns)))
				}
			} else if streamSettings.Security == "reality" {
				headBuilder.WriteString(fmt.Sprintf("&pbk=%s", *nodeXray.RealityPbk))
				headBuilder.WriteString(fmt.Sprintf("&fp=%s", streamSettings.RealitySettings.Fingerprint))
				if streamSettings.RealitySettings.SpiderX != "" {
					headBuilder.WriteString(fmt.Sprintf("&spx=%s", url.PathEscape(streamSettings.RealitySettings.SpiderX)))
				}
				shortIds := streamSettings.RealitySettings.ShortIds
				if len(shortIds) != 0 {
					headBuilder.WriteString(fmt.Sprintf("&sid=%s", shortIds[0]))
				}
				serverNames := streamSettings.RealitySettings.ServerNames
				if len(serverNames) != 0 {
					headBuilder.WriteString(fmt.Sprintf("&sni=%s", serverNames[0]))
				}
			}

			if streamSettings.Network == "ws" {
				if streamSettings.WsSettings.Path != "" {
					headBuilder.WriteString(fmt.Sprintf("&path=%s", streamSettings.WsSettings.Path))
				}
				if streamSettings.WsSettings.Headers.Host != "" {
					headBuilder.WriteString(fmt.Sprintf("&host=%s", streamSettings.WsSettings.Headers.Host))
				}
			}
		} else if *nodeXray.Protocol == constant.ProtocolShadowsocks {
			headBuilder.WriteString(fmt.Sprintf("ss://%s",
				base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s@%s:%d", *nodeXray.XraySSMethod,
					connectPass, *node.Domain, *node.Port)))))
		} else if *nodeXray.Protocol == constant.ProtocolSocks {
			settings := bo.Settings{}
			if nodeXray.Settings != nil && *nodeXray.Settings != "" {
				if err := json.Unmarshal([]byte(*nodeXray.Settings), &settings); err != nil {
					return "", errors.New(constant.NodeURLError)
				}
			}
			headBuilder.WriteString(fmt.Sprintf("socks://%s",
				base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s@%s:%d", settings.Accounts[0].User,
					settings.Accounts[0].Pass, *node.Domain, *node.Port)))))
		}
	} else if *nodeType.Id == constant.TrojanGo {
		nodeTrojanGo, err := dao.SelectNodeTrojanGoById(node.NodeSubId)
		if err != nil {
			return "", errors.New(constant.NodeURLError)
		}
		headBuilder.WriteString(fmt.Sprintf("trojan-go://%s@%s:%d?", url.PathEscape(password),
			*node.Domain, *node.Port))

		var sni string
		if nodeTrojanGo.Sni != nil && *nodeTrojanGo.Sni != "" {
			sni = *nodeTrojanGo.Sni
		} else {
			sni = *node.Domain
		}
		headBuilder.WriteString(fmt.Sprintf("sni=%s", url.PathEscape(sni)))

		if nodeTrojanGo.WebsocketEnable != nil && *nodeTrojanGo.WebsocketEnable != 0 &&
			nodeTrojanGo.WebsocketPath != nil && *nodeTrojanGo.WebsocketPath != "" {
			headBuilder.WriteString(fmt.Sprintf("&type=%s", url.PathEscape("ws")))
			headBuilder.WriteString(fmt.Sprintf("&path=%s",
				url.PathEscape(fmt.Sprintf("%s", *nodeTrojanGo.WebsocketPath))))
			if nodeTrojanGo.WebsocketHost != nil && *nodeTrojanGo.WebsocketHost != "" {
				headBuilder.WriteString(fmt.Sprintf("&host=%s",
					url.PathEscape(fmt.Sprintf("%s", *nodeTrojanGo.WebsocketHost))))
			}
			if nodeTrojanGo.SsEnable != nil && *nodeTrojanGo.SsEnable != 0 {
				headBuilder.WriteString(fmt.Sprintf("&encryption=%s", url.PathEscape(
					fmt.Sprintf("ss;%s:%s", *nodeTrojanGo.SsMethod, *nodeTrojanGo.SsPassword))))
			}
		}
	} else if *nodeType.Id == constant.Hysteria {
		nodeHysteria, err := dao.SelectNodeHysteriaById(node.NodeSubId)
		if err != nil {
			return "", errors.New(constant.NodeURLError)
		}
		headBuilder.WriteString(fmt.Sprintf("hysteria://%s:%d?protocol=%s&auth=%s&upmbps=%d&downmbps=%d",
			*node.Domain,
			*node.Port,
			*nodeHysteria.Protocol,
			password,
			*nodeHysteria.UpMbps,
			*nodeHysteria.DownMbps))
		if nodeHysteria.Obfs != nil && *nodeHysteria.Obfs != "" {
			headBuilder.WriteString(fmt.Sprintf("&obfs=xplus&obfsParam=%s", *nodeHysteria.Obfs))
		}
		if nodeHysteria.ServerName != nil && *nodeHysteria.ServerName != "" {
			headBuilder.WriteString(fmt.Sprintf("&peer=%s", *nodeHysteria.ServerName))
		}
		if nodeHysteria.Insecure != nil {
			headBuilder.WriteString(fmt.Sprintf("&insecure=%d", *nodeHysteria.Insecure))
		}
		if nodeHysteria.FastOpen != nil {
			headBuilder.WriteString(fmt.Sprintf("&fastopen=%d", *nodeHysteria.FastOpen))
		}
	} else if *nodeType.Id == constant.Hysteria2 {
		nodeHysteria2, err := dao.SelectNodeHysteria2ById(node.NodeSubId)
		if err != nil {
			return "", errors.New(constant.NodeURLError)
		}
		headBuilder.WriteString(fmt.Sprintf("hysteria2://%s@%s:%d?insecure=%d",
			password,
			*node.Domain,
			*node.Port,
			*nodeHysteria2.Insecure))
		if nodeHysteria2.ObfsPassword != nil && *nodeHysteria2.ObfsPassword != "" {
			headBuilder.WriteString(fmt.Sprintf("&obfs=salamander&obfs-password=%s", *nodeHysteria2.ObfsPassword))
		}
		if nodeHysteria2.ServerName != nil && *nodeHysteria2.ServerName != "" {
			headBuilder.WriteString(fmt.Sprintf("&sni=%s", *nodeHysteria2.ServerName))
		}
	} else if *nodeType.Id == constant.NaiveProxy {
		headBuilder.WriteString(fmt.Sprintf("naive+https://%s:%s@%s:%d",
			username,
			password,
			*node.Domain,
			*node.Port))
	}

	if node.Name != nil && *node.Name != "" {
		headBuilder.WriteString(fmt.Sprintf("#%s", url.PathEscape(*node.Name)))
	}
	return headBuilder.String(), nil
}

// NodeURLV2rayN V2rayN分享链接
func NodeURLV2rayN(node *model.Node, nodeType *model.NodeType, username string, password string) (string, error) {
	var headBuilder strings.Builder
	if *nodeType.Id == constant.Xray {
		nodeXray, err := dao.SelectNodeXrayById(node.NodeSubId)
		if err != nil {
			return "", errors.New(constant.NodeURLError)
		}
		streamSettings := bo.StreamSettings{}
		if nodeXray.StreamSettings != nil && *nodeXray.StreamSettings != "" {
			if err := json.Unmarshal([]byte(*nodeXray.StreamSettings), &streamSettings); err != nil {
				return "", errors.New(constant.NodeURLError)
			}
		}
		settings := bo.Settings{}
		if nodeXray.Settings != nil && *nodeXray.Settings != "" {
			if err := json.Unmarshal([]byte(*nodeXray.Settings), &settings); err != nil {
				return "", errors.New(constant.NodeURLError)
			}
		}

		connectPass := password

		if *nodeXray.Protocol == constant.ProtocolVless ||
			*nodeXray.Protocol == constant.ProtocolTrojan {
			if *nodeXray.Protocol == constant.ProtocolVless {
				connectPass = util.GenerateUUID(password)
			}

			headBuilder.WriteString(fmt.Sprintf("vless://%s@%s:%d?type=%s&security=%s",
				url.PathEscape(connectPass),
				*node.Domain,
				*node.Port,
				streamSettings.Network,
				streamSettings.Security))

			if nodeXray.Protocol != nil && *nodeXray.Protocol != "" {
				headBuilder.WriteString(fmt.Sprintf("&flow=%s", *nodeXray.XrayFlow))
			}

			if streamSettings.Security == "tls" {
				headBuilder.WriteString(fmt.Sprintf("&sni=%s", streamSettings.TlsSettings.ServerName))
				headBuilder.WriteString(fmt.Sprintf("&fp=%s", streamSettings.TlsSettings.Fingerprint))
				if len(streamSettings.TlsSettings.Alpn) > 0 {
					alpns := strings.Replace(strings.Trim(fmt.Sprint(streamSettings.TlsSettings.Alpn), "[]"), " ", ",", -1)
					headBuilder.WriteString(fmt.Sprintf("&alpn=%s", url.PathEscape(alpns)))
				}
			} else if streamSettings.Security == "reality" {
				headBuilder.WriteString(fmt.Sprintf("&pbk=%s", *nodeXray.RealityPbk))
				headBuilder.WriteString(fmt.Sprintf("&fp=%s", streamSettings.RealitySettings.Fingerprint))
				if streamSettings.RealitySettings.SpiderX != "" {
					headBuilder.WriteString(fmt.Sprintf("&spx=%s", url.PathEscape(streamSettings.RealitySettings.SpiderX)))
				}
				shortIds := streamSettings.RealitySettings.ShortIds
				if len(shortIds) != 0 {
					headBuilder.WriteString(fmt.Sprintf("&sid=%s", shortIds[0]))
				}
				serverNames := streamSettings.RealitySettings.ServerNames
				if len(serverNames) != 0 {
					headBuilder.WriteString(fmt.Sprintf("&sni=%s", serverNames[0]))
				}
			}

			if streamSettings.Network == "ws" {
				if streamSettings.WsSettings.Path != "" {
					headBuilder.WriteString(fmt.Sprintf("&path=%s", streamSettings.WsSettings.Path))
				}
				if streamSettings.WsSettings.Headers.Host != "" {
					headBuilder.WriteString(fmt.Sprintf("&host=%s", streamSettings.WsSettings.Headers.Host))
				}
			}
			if node.Name != nil && *node.Name != "" {
				headBuilder.WriteString(fmt.Sprintf("#%s", url.PathEscape(*node.Name)))
			}
		} else if *nodeXray.Protocol == constant.ProtocolVmess {
			connectPass = util.GenerateUUID(password)

			var v2rayNVmess bo.V2rayNVmess
			v2rayNVmess.V = "2"
			v2rayNVmess.Port = fmt.Sprintf("%d", *node.Port)
			v2rayNVmess.Add = *node.Domain
			v2rayNVmess.Id = connectPass
			v2rayNVmess.Aid = "0"
			v2rayNVmess.Scy = "none"

			if streamSettings.Security == "tls" {
				v2rayNVmess.Tls = "tls"
				v2rayNVmess.Sni = streamSettings.TlsSettings.ServerName
				v2rayNVmess.Fp = streamSettings.TlsSettings.Fingerprint
				if len(streamSettings.TlsSettings.Alpn) > 0 {
					alpns := strings.Replace(strings.Trim(fmt.Sprint(streamSettings.TlsSettings.Alpn), "[]"), " ", ",", -1)
					v2rayNVmess.Alpn = alpns
				}
			}

			if streamSettings.Network == "ws" {
				v2rayNVmess.Net = "ws"
				v2rayNVmess.Type = "none"
				if streamSettings.WsSettings.Path != "" {
					v2rayNVmess.Path = streamSettings.WsSettings.Path
				}
				if streamSettings.WsSettings.Headers.Host != "" {
					v2rayNVmess.Host = streamSettings.WsSettings.Headers.Host
				}
			}
			if node.Name != nil && *node.Name != "" {
				v2rayNVmess.Ps = *node.Name
			}
			v2rayNVmessStr, err := json.Marshal(v2rayNVmess)
			if err != nil {
				return "", errors.New(constant.NodeURLError)
			}
			headBuilder.WriteString(fmt.Sprintf("vmess://%s", base64.StdEncoding.EncodeToString(v2rayNVmessStr)))
		} else if *nodeXray.Protocol == constant.ProtocolShadowsocks {
			headBuilder.WriteString(fmt.Sprintf("ss://%s@%s:%d",
				base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", *nodeXray.XraySSMethod, connectPass))),
				*node.Domain, *node.Port))
			if node.Name != nil && *node.Name != "" {
				headBuilder.WriteString(fmt.Sprintf("#%s", url.PathEscape(*node.Name)))
			}
		} else if *nodeXray.Protocol == constant.ProtocolSocks {
			settings := bo.Settings{}
			if nodeXray.Settings != nil && *nodeXray.Settings != "" {
				if err := json.Unmarshal([]byte(*nodeXray.Settings), &settings); err != nil {
					return "", errors.New(constant.NodeURLError)
				}
			}
			headBuilder.WriteString(fmt.Sprintf("socks://%s@%s:%d",
				base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s",
					settings.Accounts[0].User,
					settings.Accounts[0].Pass))),
				*node.Domain,
				*node.Port))

			if node.Name != nil && *node.Name != "" {
				headBuilder.WriteString(fmt.Sprintf("#%s", url.PathEscape(*node.Name)))
			}
		}
	} else if *nodeType.Id == constant.TrojanGo {

	} else if *nodeType.Id == constant.Hysteria {

	} else if *nodeType.Id == constant.Hysteria2 {

	} else if *nodeType.Id == constant.NaiveProxy {

	}
	return headBuilder.String(), nil
}
