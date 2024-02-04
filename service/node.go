package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
	"strings"
	"sync"
	"trojan-panel/core"
	"trojan-panel/dao"
	"trojan-panel/dao/redis"
	"trojan-panel/model"
	"trojan-panel/model/bo"
	"trojan-panel/model/constant"
	"trojan-panel/model/dto"
	"trojan-panel/model/vo"
	"trojan-panel/util"
)

func SelectNodeById(id *uint) (*vo.NodeOneVo, error) {
	node, err := dao.SelectNodeById(id)
	if err != nil {
		return nil, err
	}
	if node != nil {
		nodeOneVo := vo.NodeOneVo{
			Id:           *node.Id,
			NodeServerId: *node.NodeServerId,
			NodeSubId:    *node.NodeSubId,
			NodeTypeId:   *node.NodeTypeId,
			Name:         *node.Name,
			Domain:       *node.Domain,
			Port:         *node.Port,
			Priority:     *node.Priority,
			CreateTime:   *node.CreateTime,
		}
		nodeTypeId := node.NodeTypeId
		switch *nodeTypeId {
		case constant.Xray:
			nodeXray, err := dao.SelectNodeXrayById(node.NodeSubId)
			if err != nil {
				return nil, err
			}
			nodeOneVo.XrayProtocol = *nodeXray.Protocol
			nodeOneVo.XrayFlow = *nodeXray.XrayFlow
			nodeOneVo.XraySSMethod = *nodeXray.XraySSMethod
			nodeOneVo.RealityPbk = *nodeXray.RealityPbk
			xraySettingEntity := vo.XraySettingEntity{}
			if nodeXray.Settings != nil && *nodeXray.Settings != "" {
				if err = json.Unmarshal([]byte(*nodeXray.Settings), &xraySettingEntity); err != nil {
					logrus.Errorln(fmt.Sprintf("Settings deserialization err: %v", err))
					return nil, errors.New(constant.SysError)
				}
			}
			nodeOneVo.XraySettingEntity = xraySettingEntity
			xrayStreamSettingsEntity := vo.XrayStreamSettingsEntity{}
			if nodeXray.StreamSettings != nil && *nodeXray.StreamSettings != "" {
				if err = json.Unmarshal([]byte(*nodeXray.StreamSettings), &xrayStreamSettingsEntity); err != nil {
					logrus.Errorln(fmt.Sprintf("StreamSettings deserialization err: %v", err))
					return nil, errors.New(constant.SysError)
				}
			}
			nodeOneVo.XrayStreamSettingsEntity = xrayStreamSettingsEntity
			nodeOneVo.XrayTag = *nodeXray.Tag
		case constant.TrojanGo:
			nodeTrojanGo, err := dao.SelectNodeTrojanGoById(node.NodeSubId)
			if err != nil {
				return nil, err
			}
			nodeOneVo.TrojanGoSni = *nodeTrojanGo.Sni
			nodeOneVo.TrojanGoMuxEnable = *nodeTrojanGo.MuxEnable
			nodeOneVo.TrojanGoWebsocketEnable = *nodeTrojanGo.WebsocketEnable
			nodeOneVo.TrojanGoWebsocketPath = *nodeTrojanGo.WebsocketPath
			nodeOneVo.TrojanGoWebsocketHost = *nodeTrojanGo.WebsocketHost
			nodeOneVo.TrojanGoSsEnable = *nodeTrojanGo.SsEnable
			nodeOneVo.TrojanGoSsMethod = *nodeTrojanGo.SsMethod
			nodeOneVo.TrojanGoSsPassword = *nodeTrojanGo.SsPassword
		case constant.Hysteria:
			nodeHysteria, err := dao.SelectNodeHysteriaById(node.NodeSubId)
			if err != nil {
				return nil, err
			}
			nodeOneVo.HysteriaProtocol = *nodeHysteria.Protocol
			nodeOneVo.HysteriaObfs = *nodeHysteria.Obfs
			nodeOneVo.HysteriaUpMbps = *nodeHysteria.UpMbps
			nodeOneVo.HysteriaDownMbps = *nodeHysteria.DownMbps
			nodeOneVo.HysteriaServerName = *nodeHysteria.ServerName
			nodeOneVo.HysteriaInsecure = *nodeHysteria.Insecure
			nodeOneVo.HysteriaFastOpen = *nodeHysteria.FastOpen
		case constant.Hysteria2:
			nodeHysteria2, err := dao.SelectNodeHysteria2ById(node.NodeSubId)
			if err != nil {
				return nil, err
			}
			nodeOneVo.Hysteria2ObfsPassword = *nodeHysteria2.ObfsPassword
			nodeOneVo.Hysteria2UpMbps = *nodeHysteria2.UpMbps
			nodeOneVo.Hysteria2DownMbps = *nodeHysteria2.DownMbps
			nodeOneVo.Hysteria2ServerName = *nodeHysteria2.ServerName
			nodeOneVo.Hysteria2Insecure = *nodeHysteria2.Insecure
		}
		return &nodeOneVo, nil
	}
	return nil, errors.New(constant.NodeNotExist)
}
func SelectNodeInfo(id *uint, c *gin.Context) (*vo.NodeOneVo, error) {

	nodeOneVo, err := SelectNodeById(id)
	if err != nil {
		return nil, err
	}
	accountInfo := GetCurrentAccount(c)
	account, err := dao.SelectAccountByUsername(&accountInfo.Username)
	if err != nil {
		return nil, err
	}
	nodeOneVo.Password = *account.Pass
	if nodeOneVo.NodeTypeId == constant.Xray && (nodeOneVo.XrayProtocol == "vless" || nodeOneVo.XrayProtocol == "vmess") {
		nodeOneVo.Uuid = util.GenerateUUID(*account.Pass)
		nodeOneVo.AlterId = 0
	}
	if nodeOneVo.NodeTypeId == constant.NaiveProxy {
		nodeOneVo.NaiveProxyUsername = accountInfo.Username
	}
	return nodeOneVo, nil
}

func CreateNode(token string, nodeCreateDto dto.NodeCreateDto) error {
	// 校验端口
	if nodeCreateDto.Port != nil && (*nodeCreateDto.Port <= 100 || *nodeCreateDto.Port >= 30000) {
		return errors.New(constant.PortRangeError)
	}

	// 校验名称
	countName, err := dao.CountNodeByNameAndNodeServerId(nil, nodeCreateDto.Name, nil)
	if err != nil {
		return err
	}
	if countName > 0 {
		return errors.New(constant.NodeNameExist)
	}

	nodeServer, err := dao.SelectNodeServer(map[string]interface{}{"id": *nodeCreateDto.NodeServerId})
	if err != nil {
		return err
	}

	systemName := constant.SystemName
	systemConfig, err := SelectSystemByName(&systemName)
	if err != nil {
		return err
	}

	var nodeId uint
	mutex, err := redis.RsLock(constant.CreateNodeLock)
	if err != nil {
		return err
	}
	// Grpc添加节点
	GrpcAddNode(token, *nodeServer.Ip, *nodeServer.GrpcPort, &core.NodeAddDto{
		NodeTypeId: uint64(*nodeCreateDto.NodeTypeId),
		Port:       uint64(*nodeCreateDto.Port),
		Domain:     *nodeCreateDto.Domain,

		//  Xray
		XrayTemplate:       systemConfig.XrayTemplate,
		XrayFlow:           *nodeCreateDto.XrayFlow,
		XraySSMethod:       *nodeCreateDto.XraySSMethod,
		XrayProtocol:       *nodeCreateDto.XrayProtocol,
		XraySettings:       *nodeCreateDto.XraySettings,
		XrayStreamSettings: *nodeCreateDto.XrayStreamSettings,
		XrayTag:            *nodeCreateDto.XrayTag,
		XraySniffing:       *nodeCreateDto.XraySniffing,
		XrayAllocate:       *nodeCreateDto.XrayAllocate,
		// Trojan Go
		TrojanGoSni:             *nodeCreateDto.TrojanGoSni,
		TrojanGoMuxEnable:       uint64(*nodeCreateDto.TrojanGoMuxEnable),
		TrojanGoWebsocketEnable: uint64(*nodeCreateDto.TrojanGoWebsocketEnable),
		TrojanGoWebsocketPath:   *nodeCreateDto.TrojanGoWebsocketPath,
		TrojanGoWebsocketHost:   *nodeCreateDto.TrojanGoWebsocketHost,
		TrojanGoSSEnable:        uint64(*nodeCreateDto.TrojanGoSsEnable),
		TrojanGoSSMethod:        *nodeCreateDto.TrojanGoSsMethod,
		TrojanGoSSPassword:      *nodeCreateDto.TrojanGoSsPassword,
		// Hysteria
		HysteriaProtocol: *nodeCreateDto.HysteriaProtocol,
		HysteriaObfs:     *nodeCreateDto.HysteriaObfs,
		HysteriaUpMbps:   int64(*nodeCreateDto.HysteriaUpMbps),
		HysteriaDownMbps: int64(*nodeCreateDto.HysteriaDownMbps),
		// Hysteria2
		Hysteria2ObfsPassword: *nodeCreateDto.Hysteria2ObfsPassword,
		Hysteria2UpMbps:       int64(*nodeCreateDto.Hysteria2UpMbps),
		Hysteria2DownMbps:     int64(*nodeCreateDto.Hysteria2DownMbps),
	})
	// 数据插入到数据库中
	if *nodeCreateDto.NodeTypeId == constant.Xray {
		nodeXray := model.NodeXray{
			Protocol:       nodeCreateDto.XrayProtocol,
			XrayFlow:       nodeCreateDto.XrayFlow,
			XraySSMethod:   nodeCreateDto.XraySSMethod,
			RealityPbk:     nodeCreateDto.RealityPbk,
			Settings:       nodeCreateDto.XraySettings,
			StreamSettings: nodeCreateDto.XrayStreamSettings,
			Tag:            nodeCreateDto.XrayTag,
			Sniffing:       nodeCreateDto.XraySniffing,
			Allocate:       nodeCreateDto.XrayAllocate,
		}
		nodeId, err = dao.CreateNodeXray(&nodeXray)
		if err != nil {
			return err
		}
	} else if *nodeCreateDto.NodeTypeId == constant.TrojanGo {
		trojanGo := model.NodeTrojanGo{
			Sni:             nodeCreateDto.TrojanGoSni,
			MuxEnable:       nodeCreateDto.TrojanGoMuxEnable,
			WebsocketEnable: nodeCreateDto.TrojanGoWebsocketEnable,
			WebsocketPath:   nodeCreateDto.TrojanGoWebsocketPath,
			WebsocketHost:   nodeCreateDto.TrojanGoWebsocketHost,
			SsEnable:        nodeCreateDto.TrojanGoSsEnable,
			SsMethod:        nodeCreateDto.TrojanGoSsMethod,
			SsPassword:      nodeCreateDto.TrojanGoSsPassword,
		}
		nodeId, err = dao.CreateNodeTrojanGo(&trojanGo)
		if err != nil {
			return err
		}
	} else if *nodeCreateDto.NodeTypeId == constant.Hysteria {
		hysteria := model.NodeHysteria{
			Protocol:   nodeCreateDto.HysteriaProtocol,
			Obfs:       nodeCreateDto.HysteriaObfs,
			UpMbps:     nodeCreateDto.HysteriaUpMbps,
			DownMbps:   nodeCreateDto.HysteriaDownMbps,
			ServerName: nodeCreateDto.HysteriaServerName,
			Insecure:   nodeCreateDto.HysteriaInsecure,
			FastOpen:   nodeCreateDto.HysteriaFastOpen,
		}
		nodeId, err = dao.CreateNodeHysteria(&hysteria)
		if err != nil {
			return err
		}
	} else if *nodeCreateDto.NodeTypeId == constant.Hysteria2 {
		hysteria2 := model.NodeHysteria2{
			ObfsPassword: nodeCreateDto.Hysteria2ObfsPassword,
			UpMbps:       nodeCreateDto.Hysteria2UpMbps,
			DownMbps:     nodeCreateDto.Hysteria2DownMbps,
			ServerName:   nodeCreateDto.Hysteria2ServerName,
			Insecure:     nodeCreateDto.Hysteria2Insecure,
		}
		nodeId, err = dao.CreateNodeHysteria2(&hysteria2)
		if err != nil {
			return err
		}
	}

	// 在主表中插入数据
	node := model.Node{
		NodeServerId:       nodeCreateDto.NodeServerId,
		NodeSubId:          &nodeId,
		NodeTypeId:         nodeCreateDto.NodeTypeId,
		Name:               nodeCreateDto.Name,
		NodeServerIp:       nodeServer.Ip,
		NodeServerGrpcPort: nodeServer.GrpcPort,
		Domain:             nodeCreateDto.Domain,
		Port:               nodeCreateDto.Port,
		Priority:           nodeCreateDto.Priority,
	}
	if err = dao.CreateNode(&node); err != nil {
		return err
	}
	redis.RsUnLock(mutex)
	return nil
}

func SelectNodePage(queryName *string, nodeServerId *uint, pageNum *uint, pageSize *uint, c *gin.Context) (*vo.NodePageVo, error) {
	nodePage, total, err := dao.SelectNodePage(queryName, nodeServerId, pageNum, pageSize)
	if err != nil {
		return nil, err
	}
	nodeBos := make([]bo.NodeBo, 0)
	for _, item := range *nodePage {
		nodeBo := bo.NodeBo{
			Id:                 *item.Id,
			NodeServerId:       *item.NodeServerId,
			NodeSubId:          *item.NodeSubId,
			NodeTypeId:         *item.NodeTypeId,
			Name:               *item.Name,
			NodeServerIp:       *item.NodeServerIp,
			NodeServerGrpcPort: *item.NodeServerGrpcPort,
			Domain:             *item.Domain,
			Port:               *item.Port,
			Priority:           *item.Priority,
			CreateTime:         *item.CreateTime,
		}
		nodeBos = append(nodeBos, nodeBo)
	}

	account := GetCurrentAccount(c)
	if util.IsAdmin(account.Roles) {
		token := util.GetToken(c)
		var nodeMap sync.Map
		var wg sync.WaitGroup
		wg.Add(len(nodeBos))
		for i := range nodeBos {
			indexI := i
			go func() {
				var ip = nodeBos[indexI].NodeServerIp
				var grpcPort = nodeBos[indexI].NodeServerGrpcPort
				var nodeTypeId = nodeBos[indexI].NodeTypeId
				var port = nodeBos[indexI].Port
				status, ok := nodeMap.Load(fmt.Sprintf("%s:%d:%d", ip, nodeTypeId, port))
				if ok {
					nodeBos[indexI].Status = status.(int)
				} else {
					var nodeState int
					nodeStateVo, err := core.GetNodeState(token, ip, grpcPort, nodeTypeId, port)
					if err != nil || nodeStateVo.GetStatus() == 0 {
						nodeState = 0
					} else {
						nodeState = 1
					}
					nodeBos[indexI].Status = nodeState
					nodeMap.Store(fmt.Sprintf("%s:%d:%d", ip, nodeTypeId, port), nodeState)
				}
				wg.Done()
			}()
		}
		wg.Wait()
	}

	nodeVos := make([]vo.NodeVo, 0)
	for _, item := range nodeBos {
		nodeVo := vo.NodeVo{
			Id:           item.Id,
			NodeServerId: item.NodeServerId,
			NodeSubId:    item.NodeSubId,
			NodeTypeId:   item.NodeTypeId,
			Name:         item.Name,
			Domain:       item.Domain,
			Port:         item.Port,
			Priority:     item.Priority,
			CreateTime:   item.CreateTime,
			Status:       item.Status,
		}
		nodeVos = append(nodeVos, nodeVo)
	}

	nodePageVo := vo.NodePageVo{
		BaseVoPage: vo.BaseVoPage{
			PageNum:  *pageNum,
			PageSize: *pageSize,
			Total:    total,
		},
		Nodes: nodeVos,
	}
	return &nodePageVo, nil
}

// DeleteNodeById 删除远程节点 删除分表 删除主表
func DeleteNodeById(token string, id *uint) error {
	mutex, err := redis.RsLock(constant.DeleteNodeByIdLock)
	if err != nil {
		return err
	}
	node, err := dao.SelectNodeById(id)
	if err != nil {
		return err
	}
	GrpcRemoveNode(token, *node.NodeServerIp, *node.NodeServerGrpcPort, *node.Port, *node.NodeTypeId)
	if *node.NodeTypeId == constant.Xray {
		if err := dao.DeleteNodeXrayById(node.NodeSubId); err != nil {
			return err
		}
	} else if *node.NodeTypeId == constant.TrojanGo {
		if err := dao.DeleteNodeTrojanGoById(node.NodeSubId); err != nil {
			return err
		}
	} else if *node.NodeTypeId == constant.Hysteria {
		if err := dao.DeleteNodeHysteriaById(node.NodeSubId); err != nil {
			return err
		}
	} else if *node.NodeTypeId == constant.Hysteria2 {
		if err := dao.DeleteNodeHysteria2ById(node.NodeSubId); err != nil {
			return err
		}
	}
	if err = dao.DeleteNodeById(id); err != nil {
		return err
	}
	redis.RsUnLock(mutex)
	return nil
}

func UpdateNodeById(token string, nodeUpdateDto *dto.NodeUpdateDto) error {
	// 校验端口
	if nodeUpdateDto.Port != nil && (*nodeUpdateDto.Port <= 100 || *nodeUpdateDto.Port >= 30000) {
		return errors.New(constant.PortRangeError)
	}

	// 校验名称
	count, err := dao.CountNodeByNameAndNodeServerId(nodeUpdateDto.Id, nodeUpdateDto.Name, nil)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New(constant.NodeNameExist)
	}

	nodeServer, err := dao.SelectNodeServer(map[string]interface{}{"id": *nodeUpdateDto.NodeServerId})
	if err != nil {
		return err
	}

	systemName := constant.SystemName
	systemConfig, err := SelectSystemByName(&systemName)
	if err != nil {
		return err
	}

	mutex, err := redis.RsLock(constant.UpdateNodeByIdLock)
	if err != nil {
		return err
	}

	nodeEntity, err := dao.SelectNodeById(nodeUpdateDto.Id)
	if err != nil {
		return err
	}
	// Grpc的操作
	GrpcRemoveNode(token, *nodeEntity.NodeServerIp, *nodeEntity.NodeServerGrpcPort, *nodeEntity.Port, *nodeEntity.NodeTypeId)
	GrpcAddNode(token, *nodeServer.Ip, *nodeServer.GrpcPort, &core.NodeAddDto{
		NodeTypeId: uint64(*nodeUpdateDto.NodeTypeId),
		Port:       uint64(*nodeUpdateDto.Port),
		Domain:     *nodeUpdateDto.Domain,

		//  Xray
		XrayTemplate:       systemConfig.XrayTemplate,
		XrayProtocol:       *nodeUpdateDto.XrayProtocol,
		XrayFlow:           *nodeUpdateDto.XrayFlow,
		XraySSMethod:       *nodeUpdateDto.XraySSMethod,
		XraySettings:       *nodeUpdateDto.XraySettings,
		XrayStreamSettings: *nodeUpdateDto.XrayStreamSettings,
		XrayTag:            *nodeUpdateDto.XrayTag,
		XraySniffing:       *nodeUpdateDto.XraySniffing,
		XrayAllocate:       *nodeUpdateDto.XrayAllocate,
		// Trojan Go
		TrojanGoSni:             *nodeUpdateDto.TrojanGoSni,
		TrojanGoMuxEnable:       uint64(*nodeUpdateDto.TrojanGoMuxEnable),
		TrojanGoWebsocketEnable: uint64(*nodeUpdateDto.TrojanGoWebsocketEnable),
		TrojanGoWebsocketPath:   *nodeUpdateDto.TrojanGoWebsocketPath,
		TrojanGoWebsocketHost:   *nodeUpdateDto.TrojanGoWebsocketHost,
		TrojanGoSSEnable:        uint64(*nodeUpdateDto.TrojanGoSsEnable),
		TrojanGoSSMethod:        *nodeUpdateDto.TrojanGoSsMethod,
		TrojanGoSSPassword:      *nodeUpdateDto.TrojanGoSsPassword,
		// Hysteria
		HysteriaProtocol: *nodeUpdateDto.HysteriaProtocol,
		HysteriaObfs:     *nodeUpdateDto.HysteriaObfs,
		HysteriaUpMbps:   int64(*nodeUpdateDto.HysteriaUpMbps),
		HysteriaDownMbps: int64(*nodeUpdateDto.HysteriaDownMbps),
		// Hysteria2
		Hysteria2ObfsPassword: *nodeUpdateDto.Hysteria2ObfsPassword,
		Hysteria2UpMbps:       int64(*nodeUpdateDto.Hysteria2UpMbps),
		Hysteria2DownMbps:     int64(*nodeUpdateDto.Hysteria2DownMbps),
	})

	if *nodeUpdateDto.NodeTypeId == *nodeEntity.NodeTypeId {
		// 没有修改节点类型的情况
		if *nodeEntity.NodeTypeId == constant.Xray {
			nodeXray := model.NodeXray{
				Id:             nodeEntity.NodeSubId,
				Protocol:       nodeUpdateDto.XrayProtocol,
				XrayFlow:       nodeUpdateDto.XrayFlow,
				XraySSMethod:   nodeUpdateDto.XraySSMethod,
				Settings:       nodeUpdateDto.XraySettings,
				StreamSettings: nodeUpdateDto.XrayStreamSettings,
				Tag:            nodeUpdateDto.XrayTag,
				Sniffing:       nodeUpdateDto.XraySniffing,
				Allocate:       nodeUpdateDto.XrayAllocate,
			}
			if err = dao.UpdateNodeXrayById(&nodeXray); err != nil {
				return err
			}
		} else if *nodeEntity.NodeTypeId == constant.TrojanGo {
			nodeTrojanGo := model.NodeTrojanGo{
				Id:              nodeEntity.NodeSubId,
				Sni:             nodeUpdateDto.TrojanGoSni,
				MuxEnable:       nodeUpdateDto.TrojanGoMuxEnable,
				WebsocketEnable: nodeUpdateDto.TrojanGoWebsocketEnable,
				WebsocketPath:   nodeUpdateDto.TrojanGoWebsocketPath,
				SsEnable:        nodeUpdateDto.TrojanGoSsEnable,
				SsMethod:        nodeUpdateDto.TrojanGoSsMethod,
				SsPassword:      nodeUpdateDto.TrojanGoSsPassword,
			}
			if err = dao.UpdateNodeTrojanGoById(&nodeTrojanGo); err != nil {
				return err
			}
		} else if *nodeEntity.NodeTypeId == constant.Hysteria {
			nodeHysteria := model.NodeHysteria{
				Id:         nodeEntity.NodeSubId,
				Protocol:   nodeUpdateDto.HysteriaProtocol,
				Obfs:       nodeUpdateDto.HysteriaObfs,
				UpMbps:     nodeUpdateDto.HysteriaUpMbps,
				DownMbps:   nodeUpdateDto.HysteriaDownMbps,
				ServerName: nodeUpdateDto.HysteriaServerName,
				Insecure:   nodeUpdateDto.HysteriaInsecure,
				FastOpen:   nodeUpdateDto.HysteriaFastOpen,
			}
			if err = dao.UpdateNodeHysteriaById(&nodeHysteria); err != nil {
				return err
			}
		} else if *nodeEntity.NodeTypeId == constant.Hysteria2 {
			nodeHysteria2 := model.NodeHysteria2{
				Id:           nodeEntity.NodeSubId,
				ObfsPassword: nodeUpdateDto.Hysteria2ObfsPassword,
				UpMbps:       nodeUpdateDto.Hysteria2UpMbps,
				DownMbps:     nodeUpdateDto.Hysteria2DownMbps,
				ServerName:   nodeUpdateDto.Hysteria2ServerName,
				Insecure:     nodeUpdateDto.Hysteria2Insecure,
			}
			if err = dao.UpdateNodeHysteria2ById(&nodeHysteria2); err != nil {
				return err
			}
		}
		if *nodeEntity.NodeServerId != *nodeUpdateDto.NodeServerId ||
			*nodeEntity.Name != *nodeUpdateDto.Name ||
			*nodeEntity.NodeServerIp != *nodeServer.Ip ||
			*nodeEntity.Domain != *nodeUpdateDto.Domain ||
			*nodeEntity.Port != *nodeUpdateDto.Port ||
			*nodeEntity.Priority != *nodeUpdateDto.Priority {
			node := model.Node{
				Id:           nodeUpdateDto.Id,
				NodeServerId: nodeUpdateDto.NodeServerId,
				Name:         nodeUpdateDto.Name,
				NodeServerIp: nodeServer.Ip,
				Domain:       nodeUpdateDto.Domain,
				Port:         nodeUpdateDto.Port,
				Priority:     nodeUpdateDto.Priority,
			}
			if err = dao.UpdateNodeById(&node); err != nil {
				return err
			}
		}
	} else {
		// 修改了节点类型的情况 需要删除分库的数据，然后重新再插入
		if *nodeEntity.NodeTypeId == constant.Xray {
			if err = dao.DeleteNodeXrayById(nodeEntity.NodeSubId); err != nil {
				return err
			}
		} else if *nodeEntity.NodeTypeId == constant.TrojanGo {
			if err = dao.DeleteNodeTrojanGoById(nodeEntity.NodeSubId); err != nil {
				return err
			}
		} else if *nodeEntity.NodeTypeId == constant.Hysteria {
			if err = dao.DeleteNodeHysteriaById(nodeEntity.NodeSubId); err != nil {
				return err
			}
		} else if *nodeEntity.NodeTypeId == constant.Hysteria2 {
			if err = dao.DeleteNodeHysteria2ById(nodeEntity.NodeSubId); err != nil {
				return err
			}
		}

		// 修改了节点类型
		var nodeId uint
		if *nodeUpdateDto.NodeTypeId == constant.Xray {
			nodeXray := model.NodeXray{
				Protocol:       nodeUpdateDto.XrayProtocol,
				XrayFlow:       nodeUpdateDto.XrayFlow,
				XraySSMethod:   nodeUpdateDto.XraySSMethod,
				Settings:       nodeUpdateDto.XraySettings,
				StreamSettings: nodeUpdateDto.XrayStreamSettings,
				Tag:            nodeUpdateDto.XrayTag,
				Sniffing:       nodeUpdateDto.XraySniffing,
				Allocate:       nodeUpdateDto.XrayAllocate,
			}
			nodeId, err = dao.CreateNodeXray(&nodeXray)
			if err != nil {
				return nil
			}
		} else if *nodeUpdateDto.NodeTypeId == constant.TrojanGo {
			trojanGo := model.NodeTrojanGo{
				Sni:             nodeUpdateDto.TrojanGoSni,
				MuxEnable:       nodeUpdateDto.TrojanGoMuxEnable,
				WebsocketEnable: nodeUpdateDto.TrojanGoWebsocketEnable,
				WebsocketPath:   nodeUpdateDto.TrojanGoWebsocketPath,
				WebsocketHost:   nodeUpdateDto.TrojanGoWebsocketHost,
				SsEnable:        nodeUpdateDto.TrojanGoSsEnable,
				SsMethod:        nodeUpdateDto.TrojanGoSsMethod,
				SsPassword:      nodeUpdateDto.TrojanGoSsPassword,
			}
			nodeId, err = dao.CreateNodeTrojanGo(&trojanGo)
			if err != nil {
				return nil
			}
		} else if *nodeUpdateDto.NodeTypeId == constant.Hysteria {
			hysteria := model.NodeHysteria{
				Protocol:   nodeUpdateDto.HysteriaProtocol,
				Obfs:       nodeUpdateDto.HysteriaObfs,
				UpMbps:     nodeUpdateDto.HysteriaUpMbps,
				DownMbps:   nodeUpdateDto.HysteriaDownMbps,
				ServerName: nodeUpdateDto.HysteriaServerName,
				Insecure:   nodeUpdateDto.HysteriaInsecure,
				FastOpen:   nodeUpdateDto.HysteriaFastOpen,
			}
			nodeId, err = dao.CreateNodeHysteria(&hysteria)
			if err != nil {
				return nil
			}
		} else if *nodeUpdateDto.NodeTypeId == constant.Hysteria2 {
			hysteria2 := model.NodeHysteria2{
				ObfsPassword: nodeUpdateDto.Hysteria2ObfsPassword,
				UpMbps:       nodeUpdateDto.Hysteria2UpMbps,
				DownMbps:     nodeUpdateDto.Hysteria2DownMbps,
				ServerName:   nodeUpdateDto.Hysteria2ServerName,
				Insecure:     nodeUpdateDto.Hysteria2Insecure,
			}
			nodeId, err = dao.CreateNodeHysteria2(&hysteria2)
			if err != nil {
				return nil
			}
		}

		node := model.Node{
			Id:                 nodeUpdateDto.Id,
			NodeServerId:       nodeUpdateDto.NodeServerId,
			NodeSubId:          &nodeId,
			NodeTypeId:         nodeUpdateDto.NodeTypeId,
			Name:               nodeUpdateDto.Name,
			NodeServerIp:       nodeServer.Ip,
			NodeServerGrpcPort: nodeServer.GrpcPort,
			Domain:             nodeUpdateDto.Domain,
			Port:               nodeUpdateDto.Port,
			Priority:           nodeUpdateDto.Priority,
		}
		if err = dao.UpdateNodeById(&node); err != nil {
			return err
		}
	}
	redis.RsUnLock(mutex)
	return nil
}

func NodeQRCode(accountId *uint, username *string, id *uint, clientType *string) ([]byte, error) {
	nodeUrl, nodeTypeId, err := NodeURL(accountId, username, id, clientType)
	if err != nil {
		return nil, err
	}
	if nodeUrl == "" {
		return nil, errors.New(constant.NodeURLError)
	}
	if nodeTypeId == constant.NaiveProxy {
		nodeUrl = strings.TrimPrefix(nodeUrl, "naive+https://")
		nodeUrl = fmt.Sprintf("https://%s", base64.StdEncoding.EncodeToString([]byte(nodeUrl)))
	}
	// 生成二维码
	qrCode, err := qrcode.Encode(nodeUrl, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	return qrCode, nil
}

// NodeURL
// xray: https://github.com/XTLS/Xray-core/issues/91
// trojan-go: https://p4gefau1t.github.io/trojan-go/developer/url/
// hysteria:https://github.com/HyNetwork/hysteria/wiki/URI-Scheme
func NodeURL(accountId *uint, username *string, id *uint, clientType *string) (string, uint, error) {

	node, err := dao.SelectNodeById(id)
	if err != nil {
		return "", 0, errors.New(constant.NodeURLError)
	}

	nodeType, err := dao.SelectNodeTypeById(node.NodeTypeId)
	if err != nil {
		return "", 0, errors.New(constant.NodeURLError)
	}

	password, err := dao.SelectConnectPassword(accountId, nil)
	if err != nil {
		return "", 0, errors.New(constant.NodeURLError)
	}
	var nodeURL string
	// 默认使用Shadowrocket分享链接
	if clientType == nil || *clientType == "" || *clientType == constant.Shadowrocket {
		nodeURL, err = NodeURLShadowrocket(node, nodeType, *username, password)
	} else if *clientType == constant.V2rayN {
		nodeURL, err = NodeURLV2rayN(node, nodeType, *username, password)
	}
	if err != nil {
		return "", 0, errors.New(constant.NodeURLError)
	}
	return nodeURL, *nodeType.Id, nil
}

func CountNode() (int, error) {
	return dao.CountNode()
}

func GrpcAddNode(token string, ip string, grpcPort uint, nodeAddDto *core.NodeAddDto) {
	_ = core.AddNode(token, ip, grpcPort, nodeAddDto)
}

func GrpcRemoveNode(token string, ip string, grpcPort uint, port uint, nodeTypeId uint) {
	_ = core.RemoveNode(token, ip, grpcPort, &core.NodeRemoveDto{
		NodeTypeId: uint64(nodeTypeId),
		Port:       uint64(port),
	})
}

func NodeDefault() (vo.NodeDefaultVo, error) {
	var nodeDefaultVo vo.NodeDefaultVo
	publicKey, privateKey, err := util.ExecuteX25519()
	if err != nil {
		return nodeDefaultVo, errors.New(constant.SysError)
	}
	nodeDefaultVo.PublicKey = publicKey
	nodeDefaultVo.PrivateKey = privateKey
	nodeDefaultVo.ShortId = util.GenerateShortId()
	nodeDefaultVo.SpiderX = fmt.Sprintf("/%s", util.RandString(8))
	return nodeDefaultVo, nil
}
