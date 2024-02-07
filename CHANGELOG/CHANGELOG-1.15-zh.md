# Release 1.15

我们很高兴宣布Antrea v1.15的发布，本次版本更新带来了很多强大的功能和改进！

首先，引入了NodeNetworkPolicy功能，允许用户将ClusterNetworkPolicy应用于Kubernetes节点，为Pod和节点之间提供一致的安全特性。

其次，Egress新增支持使用与默认节点子网不同的子网中的IP，特别适用于用户希望使用VLAN将出口流量与集群内流量分开的场景。

第三，Antrea新增CNI迁移工具，简化了从特定的CNI迁移到Antrea的流程，确保用户在其已建立的集群上能够顺畅切换来获得Antrea的丰富功能。

第四，Antrea现在支持第7层网络流导出，为用户提供了针对应用程序流量模式更全面观测能力。

最后，Antrea在多个维度上提高了可用性和兼容性：为Agent和Controller提供了单独的容器镜像，以最小化镜像大小并加快部署新Antrea版本的速度；Flexible IPAM现在支持多播流量；
同时Antrea可以用作Talos集群的CNI；在AKS中也已验证encap模式，欢迎用户在AWS体验尝试。

## 1.15.0

### 新增功能

- Egress功能现在支持使用与默认节点子网不同的子网中的IP。([#5799](https://github.com/antrea-io/antrea/pull/5799), [@tnqn])

默认情况下，假定从ExternalIPPool分配的IP与节点IP在同一子网中。从Antrea v1.15开始，
可以从与节点IP不同的子网中分配IP。

为此新增了`subnetInfo`字段,可以在该字段中定义特定ExternalIPPool的子网属性。
注意在使用不同子网时：

1. 必须设置gateway和prefixLength。当目的地址和Egress IP不在同一子网中时， Antrea将通过指定的网关路由Egress流量，否则直接路由到目的地。
2. 作为可选项，如果底层网络需要，可以指定`vlan`字段。
一旦设置该值，Antrea将标记离开Egress节点的Egress流量，添加指定的VLAN ID。相应地，
Egress节点收到的目的地址为EgressIP的回复流量也应被标记为指定的VLAN ID。

使用非默认子网的ExternalIPPool的示例如下：

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ExternalIPPool
metadata:
  name: prod-external-ip-pool
spec:
  ipRanges:
  - start: 10.10.0.2
    end: 10.10.0.10
  subnetInfo:
    gateway: 10.10.0.1
    prefixLength: 24
    vlan: 10
  nodeSelector:
    matchLabels:
      network-role: egress-gateway
```

有关此功能的更多信息，请参阅 [此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/egress.md) 。


- 添加迁移工具，以支持从其他CNI迁移到Antrea。([#5677](https://github.com/antrea-io/antrea/pull/5677), [@hjiajing])

迁移过程分为三个步骤：

1. 清理旧的CNI。
2. 在集群中安装Antrea。
3. 部署Antrea迁移工具。

在Antrea启动并运行后，可以通过以下命令部署Antrea迁移工具antrea-migrator：
```bash
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-migrator.yml
```

该迁移工具作为DaemonSet在集群中运行，将原地重启集群中所有非hostNetwork的Pod，
并执行必要的网络资源清理。



有关此工具的更多信息，请参阅 [此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/migrate-to-antrea.md) 。

- 在Antrea中添加L7网络流量导出支持，可导出具有L7协议信息的网络流量。([#5218](https://github.com/antrea-io/antrea/pull/5218), [@tushartathgur])

要导出Pod或Namespace的7层流量，用户需要为Pod或Namespace添加Annotation `visibility.antrea.io/l7-export`，
并将其值设置为流量方向，例如`ingress`、`egress`或`both`。

例如，要在default Namespace中启用`ingress`方向上的7层流量导出，可以使用：
```bash
kubectl annotate pod test-pod visibility.antrea.io/l7-export=ingress
```

根据注释，流量导出器将使用字段`appProtocolName`和`httpVals`将7层流量数据导出到Flow Aggregator
或配置的IPFIX收集器。

1. `appProtocolName`字段用于指示应用层协议名称（例如`http`），如果未导出应用层数据，则为空。
2. `httpVals`存储了一个序列化的JSON字典，其中每个HTTP请求都映射到唯一的ID。
此格式使我们能够将与同一连接相关的所有HTTP流量分组到相同的导出记录中。

例如：
`"{\"0\":{\"hostname\":\"10.10.0.1\",\"url\":\"/public/\",\"http_user_agent\":\"curl/7.74.0\",\"http_content_type\":\"text/html\",\"http_method\":\"GET\",\"protocol\":\"HTTP/1.1\",\"status\":200,\"length\":153}}"`

目前该特性只支持Linux节点，且只支持`HTTP1.1`协议流量的导出。
有关此功能的更多信息，请参阅[此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/network-flow-visibility.md)。

- 新增NodeNetworkPolicy功能，允许用户将ClusterNetworkPolicy应用于Kubernetes节点。([#5658](https://github.com/antrea-io/antrea/pull/5658) [#5716](https://github.com/antrea-io/antrea/pull/5716), [@hongliangl] [@Atish-iaf])

NodeNetworkPolicy在本次版本更新中作为 Alpha 功能引入。
如下所示，在ConfigMap `antrea-config`中，必须启用一个名为NodeNetworkPolicy的功能开关。

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      NodeNetworkPolicy: true
```

也可以使用以下helm安装命令来启用功能开关：

```bash
helm install antrea antrea/antrea --namespace kube-system --set featureGates.NodeNetworkPolicy=true
```

NodeNetworkPolicy是Antrea ClusterNetworkPolicy（ACNP）的扩展。通过指定NetworkPolicy spec的`appliedTo`为`nodeSelector`字段，
将ACNP应用于`nodeSelector`所选的Kubernetes节点。

例如，如下ClusterNetworkPolicy可以控制节点到Pod的流量，在集群中定义该ClusterNetworkPolicy并应用，
标有`app=client`的Pod发往标有`kubernetes.io/hostname: k8s-node-control-plane`的节点的入口流量将被阻止：

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: restrict-http-to-node
spec:
  priority: 5
  tier: application
  appliedTo:
    - nodeSelector:
        matchLabels:
          kubernetes.io/hostname: k8s-node-control-plane
  ingress:
    - name: allow-cidr
      action: Allow
      from:
        - ipBlock:
            cidr: 10.10.0.0/16
      ports:
        - protocol: TCP
          port: 80
    - name: drop-other
      action: Drop
      ports:
        - protocol: TCP
          port: 80
```

也可以控制节点到节点或者IP段的网络流量，以下示例是阻止带有标签`kubernetes.io/hostname: k8s-node-control-plane`的节点上的流量发往
带有标签`kubernetes.io/hostname: k8s-node-worker-1`和某些IP块的节点：

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: egress-drop-node-to-node
spec:
  priority: 5
  tier: application
  appliedTo:
    - nodeSelector:
        matchLabels:
          kubernetes.io/hostname: k8s-node-control-plane
  egress:
    - name: drop-22
      action: Drop
      to:
        - nodeSelector:
            matchLabels:
              kubernetes.io/hostname: k8s-node-worker-1
        - ipBlock:
            cidr: 192.168.77.0/24
        - ipBlock:
            cidr: 10.10.0.0/24
      ports:
        - protocol: TCP
          port: 22
```

有关此功能的更多信息，请参阅 [此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/antrea-node-network-policy.md) 。

- 为Antrea Multicast功能添加Flexible IPAM支持。([#4922](https://github.com/antrea-io/antrea/pull/4922), [@ceclinux])
- 支持Talos集群运行Antrea作为CNI，并将Talos添加到K8s安装程序文档中。([#5718](https://github.com/antrea-io/antrea/pull/5718) [#5766](https://github.com/antrea-io/antrea/pull/5766), [@antoninbas])
- 在NetworkAttachmentDefinition的网络配置不包括IPAM配置时，支持Secondary Network。([#5762](https://github.com/antrea-io/antrea/pull/5762), [@jianjuns])
- 添加在AKS中以encap模式安装Antrea的说明。([#5901](https://github.com/antrea-io/antrea/pull/5901), [@antoninbas])

### 其他变更

- 将Secondary NetworkPod控制器更改为订阅CNIServer事件，以支持bridging和VLAN网络。([#5767](https://github.com/antrea-io/antrea/pull/5767), [@jianjuns])
- 为Secondary Network支持使用Antrea IPAM。([#5427](https://github.com/antrea-io/antrea/pull/5427), [@jianjuns])
- 为antrea-agent和antrea-controller创建不同的镜像，以减小总的镜像大小，加快antrea-agent和antrea-controller的启动速度。([#5856](https://github.com/antrea-io/antrea/pull/5856) [#5902](https://github.com/antrea-io/antrea/pull/5902) [#5903](https://github.com/antrea-io/antrea/pull/5903), [@jainpulkit22])
- 在使用Wireguard加密模式时不创建隧道接口（antrea-tun0）。([#5885](https://github.com/antrea-io/antrea/pull/5885) [#5909](https://github.com/antrea-io/antrea/pull/5909), [@antoninbas])
- 在Egress IP分配更改时记录事件，以便更好地进行故障诊断。([#5765](https://github.com/antrea-io/antrea/pull/5765), [@jainpulkit22])
- 更新Windows文档，完善安装指南和说明。([#5789](https://github.com/antrea-io/antrea/pull/5789), [@antoninbas])
- 根据需要自动启用IPv4/IPv6转发，不再需要用户操作或依赖其他组件。([#5833](https://github.com/antrea-io/antrea/pull/5833), [@tnqn])
- 在antrea-agent中添加跳过加载内核模块的能力，以支持一些特定的发行版（例如：Talos）。([#5754](https://github.com/antrea-io/antrea/pull/5754), [@antoninbas])
- 新增支持在Traceflow观测结果中添加NetworkPolicy规则名称。([#5667](https://github.com/antrea-io/antrea/pull/5667), [@Atish-iaf])
- 在"antctl traceflow"工具中使用Traceflow API v1beta1而不是弃用的API版本。([#5689](https://github.com/antrea-io/antrea/pull/5689), [@Atish-iaf])
- 在FlowExporter中用netip.Addr替换net.IP，以优化内存使用并提高FlowExporter的性能。([#5532](https://github.com/antrea-io/antrea/pull/5532), [@antoninbas])
- 更新antrea-agent-simulator中kubemark的镜像版本，从v1.18.4升级到v1.29.0。([#5820](https://github.com/antrea-io/antrea/pull/5820), [@luolanzone])
- 将CNI插件升级到v1.4.0。([#5747](https://github.com/antrea-io/antrea/pull/5747) [#5813](https://github.com/antrea-io/antrea/pull/5813), [@antoninbas] [@luolanzone])
- 更新Egress功能选项和如何在AWS上使用的文档。([#5436](https://github.com/antrea-io/antrea/pull/5436), [@tnqn])
- 在antrea-ipam.md文档中添加Flexible IPAM的详细设计信息。([#5339](https://github.com/antrea-io/antrea/pull/5339), [@gran-vmv])

### 修复

- 修复WireGuard加密模式和GRE隧道模式下MTU配置不正确的问题。([#5880](https://github.com/antrea-io/antrea/pull/5880) [#5926](https://github.com/antrea-io/antrea/pull/5926), [@hjiajing] [@tnqn])
- 在TrafficControl控制器中优先处理L7 NetworkPolicy流，避免Pod同时也被TrafficControl CR影响，从而可能绕过L7引擎的情况。([#5768](https://github.com/antrea-io/antrea/pull/5768), [@hongliangl])
- 在释放Pod IP之前删除OVS端口和流规则。([#5788](https://github.com/antrea-io/antrea/pull/5788), [@tnqn])
- 将NetworkPolicy存储在文件系统中作为备用数据源，以便让antre-agent在启动时无法连接到antrea-controller时回退到使用文件。([#5739](https://github.com/antrea-io/antrea/pull/5739), [@tnqn])
- 确保应用初始NetworkPolicies后才启动Pod网络转发，避免在antrea-agent重新启动时Pod的出入口流量绕过NetworkPolicy。([#5777](https://github.com/antrea-io/antrea/pull/5777), [@tnqn])
- [Windows]修复Prepare-AntreaAgent.ps1中为容器化OVS的Clean-AntreaNetwork.ps1调用。([#5859](https://github.com/antrea-io/antrea/pull/5859), [@antoninbas])
- [Windows]在Prepare-Node.ps1中添加kubelet启动参数中缺失的空格，修复kubelet不能启动的问题。([#5858](https://github.com/antrea-io/antrea/pull/5858), [@antoninbas])
- 修复由缺少参数引起的antctl trace-packet命令调用失败的问题。([#5838](https://github.com/antrea-io/antrea/pull/5838), [@luolanzone])
- 当启用Antrea proxyAll模式时，为具有ExternalIPs的Services支持Local ExternalTrafficPolicy。 ([#5795](https://github.com/antrea-io/antrea/pull/5795), [@tnqn])
- 将net.ipv4.conf.antrea-gw0.arp_announce设置为1，以修复当Node或hostNetwork Pod访问本地Pod并启用AntreaIPAM时的ARP请求泄漏问题。([#5657](https://github.com/antrea-io/antrea/pull/5657), [@gran-vmv])
- 跳过对hairpinned Service流量（Pod通过Service访问自身）的入口NetworkPolicies规则的执行。([#5687](https://github.com/antrea-io/antrea/pull/5687) [#5705](https://github.com/antrea-io/antrea/pull/5705), [@GraysonWu])
- 添加host-local IPAM GC，以避免在antrea-agent重新启动时可能的IP泄漏问题。([#5660](https://github.com/antrea-io/antrea/pull/5660), [@antoninbas])
- 修复使用基于UBI的镜像时的CrashLookBackOff问题。([#5723](https://github.com/antrea-io/antrea/pull/5723), [@antoninbas])
- 删除fillPodInfo/fillServiceInfo中的冗余日志以修复日志泛滥问题，并更新deny连接的DestinationServiceAddress。([#5592](https://github.com/antrea-io/antrea/pull/5592) [#5704](https://github.com/antrea-io/antrea/pull/5704), [@yuntanghsu])
- [Windows]增强在Windows上的HNS网络初始化，以避免一些极端情况下可能出现的问题。([#5841](https://github.com/antrea-io/antrea/pull/5841), [@XinShuYang])
- 改善故障排除，优化端点查询规则索引响应。([#5783](https://github.com/antrea-io/antrea/pull/5783), [@qiyueyao])
- 优化FQDN控制器的处理逻辑，过滤掉一些不必要的规则处理。([#5893](https://github.com/antrea-io/antrea/pull/5893), [@Dyanngg])
- [Windows]更新Windows OVS下载链接，移除无效证书，以防止安装未签名的OVS驱动。([#5839](https://github.com/antrea-io/antrea/pull/5839), [@XinShuYang])
- 修复StatefulSets上Antrea FlexibleIPAM的IP注释不起作用的问题。([#5715](https://github.com/antrea-io/antrea/pull/5715), [@gran-vmv])
- 在PrepareHNSNetwork中添加DHCP IP重试以修复可能的IP获取失败的问题。([#5819](https://github.com/antrea-io/antrea/pull/5819), [@XinShuYang])
- 修改"antctl mc deploy"以支持Antrea多集群部署在manifest更改时的更新。([#5257](https://github.com/antrea-io/antrea/pull/5257), [@luolanzone])


[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@gran-vmv]: https://github.com/gran-vmv
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@tushartathgur]: https://github.com/tushartathgur
[@yuntanghsu]: https://github.com/yuntanghsu
