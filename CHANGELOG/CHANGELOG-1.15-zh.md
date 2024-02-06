# Release 1.15

我们很高兴宣布Antrea v1.15的发布，本次版本更新带来了强大的功能和改进！

首先，引入了NodeNetworkPolicy功能，允许用户将ClusterNetworkPolicy应用于Kubernetes节点，为Pod和节点之间提供一致的安全姿态。
其次，Egress新增支持使用与默认节点子网不同的子网中的IP，特别适用于用户希望使用VLAN将出口流量与集群内流量分开的场景。
第三，Antrea新增CNI迁移工具，简化了从选定的CNI过渡到Antrea的流程，确保用户在其已建立的集群上采用Antrea丰富功能时获得顺畅的体验。
第四，Antrea现在支持第7层网络流导出，为用户提供了对其应用程序流量模式的更全面观测能力。
最后，Antrea在多个维度上提高了可用性和兼容性：为Agent和Controller提供了单独的容器镜像，以最小总体镜像大小并加快部署新Antrea版本的速度；Flexible IPAM现在支持多播流量；Antrea可以用作Talos集群的CNI；在AKS中已验证encap模式。

## 1.15.0

### 新增功能

- Egress功能现在支持使用与默认节点子网不同的子网中的IP。([#5799](https://github.com/antrea-io/antrea/pull/5799), [@tnqn])
    * 有关此功能的更多信息，请参阅[此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/egress.md)。
- 添加迁移工具，以支持从其他CNI迁移到Antrea。([#5677](https://github.com/antrea-io/antrea/pull/5677), [@hjiajing])
    * 有关此工具的更多信息，请参阅[此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/migrate-to-antrea.md)。
- 在Antrea中添加L7网络流导出支持，可导出具有L7协议信息的网络流。([#5218](https://github.com/antrea-io/antrea/pull/5218), [@tushartathgur])
    * 有关此功能的更多信息，请参阅[此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/network-flow-visibility.md)。
- 新增支持节点NetworkPolicy:NodeNetworkPolicy，允许用户将ClusterNetworkPolicy应用于Kubernetes节点。([#5658](https://github.com/antrea-io/antrea/pull/5658) [#5716](https://github.com/antrea-io/antrea/pull/5716), [@hongliangl] [@Atish-iaf])
    * 有关此功能的更多信息，请参阅[此文档](https://github.com/antrea-io/antrea/blob/release-1.15/docs/antrea-node-network-policy.md)。
- 为Antrea Multicast功能添加灵活的IPAM支持。([#4922](https://github.com/antrea-io/antrea/pull/4922), [@ceclinux])
- 支持Talos集群运行Antrea作为CNI，并将Talos添加到K8s安装程序文档中。([#5718](https://github.com/antrea-io/antrea/pull/5718) [#5766](https://github.com/antrea-io/antrea/pull/5766), [@antoninbas])
- 在NetworkAttachmentDefinition的网络配置不包括IPAM配置时，支持辅助网络。([#5762](https://github.com/antrea-io/antrea/pull/5762), [@jianjuns])
- 在AKS中添加Antrea以encap模式安装的说明。([#5901](https://github.com/antrea-io/antrea/pull/5901), [@antoninbas])

### 其他变更

- 将辅助网络Pod控制器更改为订阅CNIServer事件，以支持bridging和VLAN网络。([#5767](https://github.com/antrea-io/antrea/pull/5767), [@jianjuns])
- 为辅助网络支持使用Antrea IPAM。([#5427](https://github.com/antrea-io/antrea/pull/5427), [@jianjuns])
- 为antrea-agent和antrea-controller创建不同的image镜像，以减小总的镜像大小，加快antrea-agent和antrea-controller的启动速度。([#5856](https://github.com/antrea-io/antrea/pull/5856) [#5902](https://github.com/antrea-io/antrea/pull/5902) [#5903](https://github.com/antrea-io/antrea/pull/5903), [@jainpulkit22])
- 在使用Wireguard加密模式时不创建隧道接口（antrea-tun0）。([#5885](https://github.com/antrea-io/antrea/pull/5885) [#5909](https://github.com/antrea-io/antrea/pull/5909), [@antoninbas])
- 在Egress IP分配更改时记录事件，以便更好地进行故障排除。([#5765](https://github.com/antrea-io/antrea/pull/5765), [@jainpulkit22])
- 更新Windows文档，完善安装指南和说明。([#5789](https://github.com/antrea-io/antrea/pull/5789), [@antoninbas])
- 根据需要自动启用IPv4/IPv6转发，以消除用户干预或依赖其他组件的需要。([#5833](https://github.com/antrea-io/antrea/pull/5833), [@tnqn])
- 添加在antrea-agent中跳过加载内核模块的能力，以支持一些专业的发行版（例如：Talos）。([#5754](https://github.com/antrea-io/antrea/pull/5754), [@antoninbas])
- 在Traceflow输出中添加NetworkPolicy规则名称（rule Name）。([#5667](https://github.com/antrea-io/antrea/pull/5667), [@Atish-iaf])
- 在"antctl traceflow"工具中使用Traceflow API v1beta1而不是弃用的API版本。([#5689](https://github.com/antrea-io/antrea/pull/5689), [@Atish-iaf])
- 在FlowExporter中用netip.Addr替换net.IP，以优化内存使用并提高FlowExporter的性能。([#5532](https://github.com/antrea-io/antrea/pull/5532), [@antoninbas])
- 更新antrea-agent-simulator中kubemark的镜像版本，从v1.18.4升级到v1.29.0。([#5820](https://github.com/antrea-io/antrea/pull/5820), [@luolanzone])
- 将CNI插件升级到v1.4.0。([#5747](https://github.com/antrea-io/antrea/pull/5747) [#5813](https://github.com/antrea-io/antrea/pull/5813), [@antoninbas] [@luolanzone])
- 更新AWS上Egress功能选项和使用文档。([#5436](https://github.com/antrea-io/antrea/pull/5436), [@tnqn])
- 在antrea-ipam.md文档中中添加Flexible IPAM的详细设计信息。([#5339](https://github.com/antrea-io/antrea/pull/5339), [@gran-vmv])

### 修复

- 修复WireGuard加密模式和GRE隧道模式的MTU配置不正确的问题。([#5880](https://github.com/antrea-io/antrea/pull/5880) [#5926](https://github.com/antrea-io/antrea/pull/5926), [@hjiajing] [@tnqn])
- 在TrafficControl控制器中优先处理L7 NetworkPolicy流，以避免潜在问题即带有将流量重定向到同一Pod的TrafficControl CR可能会绕过L7引擎的情况。([#5768](https://github.com/antrea-io/antrea/pull/5768), [@hongliangl])
- 在释放Pod IP之前删除OVS端口和流规则。([#5788](https://github.com/antrea-io/antrea/pull/5788), [@tnqn])
- 将NetworkPolicy存储在文件系统中作为备用数据源，以便让antre-agent在启动时无法连接到antrea-controller时回退到使用文件。([#5739](https://github.com/antrea-io/antrea/pull/5739), [@tnqn])
- 在实现初始NetworkPolicies后，就打开Pod网络，避免在antrea-agent重新启动时到达或者经过Pod的流量绕过NetworkPolicy。([#5777](https://github.com/antrea-io/antrea/pull/5777), [@tnqn])
- [Windows]修复Prepare-AntreaAgent.ps1中为containerized OVS的Clean-AntreaNetwork.ps1调用。([#5859](https://github.com/antrea-io/antrea/pull/5859), [@antoninbas])
- [Windows]在Prepare-Node.ps1中kubelet args的位置添加缺少的空格，以便kubelet可以成功启动。([#5858](https://github.com/antrea-io/antrea/pull/5858), [@antoninbas])
- 修复由缺少参数引起的antctl trace-packet命令调用失败问题。([#5838](https://github.com/antrea-io/antrea/pull/5838), [@luolanzone])
- 当启用Antrea proxyAll模式时，为具有ExternalIPs的Services支持Local ExternalTrafficPolicy。 ([#5795](https://github.com/antrea-io/antrea/pull/5795), [@tnqn])
- 将net.ipv4.conf.antrea-gw0.arp_announce设置为1，以修复当Node或hostNetwork Pod访问本地Pod并启用AntreaIPAM时的ARP请求泄漏问题。([#5657](https://github.com/antrea-io/antrea/pull/5657), [@gran-vmv])
- 跳过对hairpinned Service流量（Pod通过Service访问自身）的入口NetworkPolicies规则的执行。([#5687](https://github.com/antrea-io/antrea/pull/5687) [#5705](https://github.com/antrea-io/antrea/pull/5705), [@GraysonWu])
- 添加host-local IPAM GC，以避免在antrea-agent重新启动时可能的IP泄漏问题。([#5660](https://github.com/antrea-io/antrea/pull/5660), [@antoninbas])
- 修复使用基于UBI的镜像时的CrashLookBackOff问题。([#5723](https://github.com/antrea-io/antrea/pull/5723), [@antoninbas])
- 删除fillPodInfo/fillServiceInfo中的冗余日志以修复日志泛滥问题，并更新deny连接的DestinationServiceAddress。([#5592](https://github.com/antrea-io/antrea/pull/5592) [#5704](https://github.com/antrea-io/antrea/pull/5704), [@yuntanghsu])
- [Windows]增强在Windows上的HNS网络初始化，以避免一些极端情况可能的问题。([#5841](https://github.com/antrea-io/antrea/pull/5841), [@XinShuYang])
- 改善故障排除，优化端点查询规则索引响应。([#5783](https://github.com/antrea-io/antrea/pull/5783), [@qiyueyao])
- 优化FQDN控制器的调协，过滤掉一些不必要的规则处理。([#5893](https://github.com/antrea-io/antrea/pull/5893), [@Dyanngg])
- [Windows]更新Windows OVS下载链接，移除无效证书，以防止未签名的OVS驱动安装。([#5839](https://github.com/antrea-io/antrea/pull/5839), [@XinShuYang])
- 修复StatefulSets上Antrea FlexibleIPAM的IP注释不起作用的问题。([#5715](https://github.com/antrea-io/antrea/pull/5715), [@gran-vmv])
- 在PrepareHNSNetwork中添加DHCP IP重试以修复潜在的IP检索故障。([#5819](https://github.com/antrea-io/antrea/pull/5819), [@XinShuYang])
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
