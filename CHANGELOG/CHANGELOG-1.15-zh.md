# Changelog 1.14

## 1.15.0

### 新增

支持使用与默认节点子网不同的子网中的IP进行Egress。
(#5799, @tnqn)
有关此功能的更多信息，请参阅此文档。
添加迁移工具，以支持从其他CNI迁移到Antrea。
(#5677, @hjiajing)
有关此工具的更多信息，请参阅此文档。
在Antrea中添加L7网络流导出支持，可导出具有L7协议信息的网络流。
(#5218, @tushartathgur)
有关此功能的更多信息，请参阅此文档。
添加一个新功能NodeNetworkPolicy，允许用户将ClusterNetworkPolicy应用于Kubernetes节点。
(#5658 #5716, @hongliangl @Atish-iaf)
有关此功能的更多信息，请参阅此文档。
为Antrea Multicast功能添加灵活的IPAM支持。
(#4922, @ceclinux)
支持Talos集群运行Antrea作为CNI，并将Talos添加到K8s安装程序文档中。
(#5718 #5766, @antoninbas)
在NetworkAttachmentDefinition的网络配置不包括IPAM配置时，支持辅助网络。
(#5762, @jianjuns)
在AKS中添加Antrea以encap模式安装的说明。
(#5901, @antoninbas)

### 更改

将辅助网络Pod控制器更改为订阅CNIServer事件，以支持桥接和VLAN网络。
(#5767, @jianjuns)
为辅助网络支持使用Antrea IPAM。
(#5427, @jianjuns)
为antrea-agent和antrea-controller创建不同的映像，以最小化总体映像大小，加快antrea-agent和antrea-controller的启动速度。
(#5856 #5902 #5903, @jainpulkit22)
在使用Wireguard加密模式时不创建隧道接口（antrea-tun0）。
(#5885 #5909, @antoninbas)
在Egress IP分配更改时记录事件，以便更好地进行故障排除。
(#5765, @jainpulkit22)
使用更清晰的安装指南和说明更新Windows文档。
(#5789, @antoninbas)
根据需要自动启用IPv4/IPv6转发，以消除用户干预或依赖其他组件的需要。
(#5833, @tnqn)
添加在antrea-agent中跳过加载内核模块的能力，以支持一些专业的发行版（例如：Talos）。
(#5754, @antoninbas)
在Traceflow观察中添加NetworkPolicy规则名称。
(#5667, @Atish-iaf)
在antctl traceflow中使用Traceflow API v1beta1而不是弃用的API版本。
(#5689, @Atish-iaf)
在FlowExporter中用netip.Addr替换net.IP，以优化内存使用并提高FlowExporter的性能。
(#5532, @antoninbas)
从v1.18.4升级kubemark到v1.29.0以用于antrea-agent-simulator。
(#5820, @luolanzone)
将CNI插件升级到v1.4.0。
(#5747 #5813, @antoninbas @luolanzone)
更新AWS云上Egress功能选项和使用的文档。
(#5436, @tnqn)
在antrea-ipam.md中添加灵活IPAM的设计详细信息。
(#5339, @gran-vmv)

### 修复

修复WireGuard加密模式和GRE隧道模式的MTU配置不正确的问题。
(#5880 #5926, @hjiajing @tnqn)
优先处理L7 NetworkPolicy流，以避免潜在问题，即具有将流量重定向到同一Pod的TrafficControl CR可能会绕过L7引擎的情况。
(#5768, @hongliangl)
在释放Pod IP之前删除OVS端口和流规则。
(#5788, @tnqn)
将NetworkPolicy存储在文件系统中作为备用数据源，以便让antre-agent在启动时无法连接到antrea-controller时回退到使用文件。
(#5739, @tnqn)
在实现初始NetworkPolicies后避免在antrea-agent重新启动时绕过NetworkPolicy绕过Pod与Pod之间的流量。
(#5777, @tnqn)
在Prepare-AntreaAgent.ps1中为containerized OVS上的Clean-AntreaNetwork.ps1调用添加。
(#5859, @antoninbas)
在Prepare-Node.ps1中kubelet args的位置添加缺少的空格，以便kubelet可以成功启动Windows。
(#5858, @antoninbas)
修复由缺少参数引起的antctl trace-packet命令失败。
(#5838, @luolanzone)
当启用Antrea proxyAll模式时，为具有ExternalIPs的Services支持Local ExternalTrafficPolicy。
(#5795, @tnqn)
将net.ipv4.conf.antrea-gw0.arp_announce设置为1，以修复当Node或hostNetwork Pod访问本地Pod并启用AntreaIPAM时的ARP请求泄漏。
(#5657, @gran-vmv)
跳过对hairpinned Service流量（Pod通过Service访问自身）的入口NetworkPolicies规则的执行。
(#5687 #5705, @GraysonWu)
在antrea-agent重新启动后避免潜在的IP泄漏问题，添加启动时的host-local IPAM GC。
(#5660, @antoninbas)
修复使用基于UBI的映像时的CrashLookBackOff问题。
(#5723, @antoninbas)
删除fillPodInfo/fillServiceInfo中的冗余日志以修复日志泛滥问题，并更新deny连接的DestinationServiceAddress。
(#5592 #5704, @yuntanghsu)
增强在Windows上的HNS网络初始化，以避免一些边缘情况。
(#5841, @XinShuYang)
改善故障排除的响应中的端点查询规则索引。
(#5783, @qiyueyao)
避免在FQDN控制器中进行不必要的规则协商。
(#5893, @Dyanngg)
将Windows OVS下载链接更新为删除无效证书以防止未签名的OVS驱动安装。
(#5839, @XinShuYang)
修复Antrea FlexibleIPAM下StatefulSets上不起作用的IP注释。
(#5715, @gran-vmv)
在PrepareHNSNetwork中添加DHCP IP重试以修复潜在的IP检索故障。
(#5819, @XinShuYang)
修改antctl mc deploy以支持Antrea Multi-cluster deployment的更新，当清单发生更改时。
(#5257, @luolanzone)
