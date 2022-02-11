# 新增

1. 新增Antrea多集群（Multi-cluster）特性，用户可以在ClusterSet内跨多个集群导入和导出Services、Endpoints，
在ClusterSet中启用集群间通信：
Antrea Multi-cluster 基于[Multi-cluster Service API](https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api)实现了跨集群间的服务通信。
在Antrea v1.5.0版本中, Antrea引入独立的多集群控制器, 用户可以通过新的ClusterSet自定义资源类型, 定义一个由管理集群和成员集群构成的多集群群组。
在群组的一个或多个成员集群中,管理员可以创建ServiceExport来导出指定的服务,其他成员集群的多集群控制器会监视并导入来自其他成员的服务和端点, 
在Pod IP互相可达的情况下, 应用可以像访问普通服务一样访问导入的多集群服务, 从而实现不同成员集群间的服务访问。
[]()
进一步了解该特性和功能，请参考：https://github.com/antrea-io/antrea/blob/v1.5.0/docs/multicluster/getting-started.md    
想了解更多关于多集群架构和设计内容，请参考：https://github.com/antrea-io/antrea/blob/v1.5.0/docs/multicluster/architecture.md
   (#3199, @luolanzone @aravindakidambi @bangqipropel @hjiajing @Dyanngg @suwang48404 @abhiraut) [Alpha]
2. 新增对多播（multicast）的支持，允许在集群网络内（即Pod之间），以及外部网络和集群网络之间转发多播流量。     
注：目前只在Linux节点IPv4流量的noEncap模式下支持该功能；    
   (#2652 #3142 #2835 #3171 #2986, @wenyingd @ceclinux @XinShuYang) [Alpha - Feature Gate: Multicast]
3. AntreaIPAM支持在Deployment和StatefulSet的Pod/PodTemplate上添加IPPool/IP annotations：
StatefulSet的Pod从IPPool分配的IP，在Pod重启之后仍会保持不变；
Pod上的IPPool annotations比Namespace上的IPPool annotations优先级更高；
关于该特性的更多细节请参考：https://github.com/antrea-io/antrea/blob/v1.5.0/docs/antrea-ipam.md     
   (#3093 #3042 #3141 #3164 #3146, @gran-vmv @annakhm)
4. 添加对SR-IOV辅助网络的支持。Antrea现在可以为使用SR-IOV VFs的裸金属节点上运行的Pod创建辅助网络接口； (#2651, @arunvelayutham) [Alpha - Feature Gate: SecondaryNetwork]
5. 支持从ExternalIPPool中为LoadBalancer的Services分配IP，注：目前为Alpha特性，需打开ServiceExternalIP开关；[Alpha - Feature Gate: ServiceExternalIP]
6. antctl工具新增对flow aggregator Pod的支持： 
使用'antctl get log-level'更改日志级别；
使用'antctl get flowrecords [-o json]'导出流记录；
使用'antctl get recordmetrics'导出流记录监控指标；
   (#2878, @yanjunz97)
7. Antrea原生NetworkPolicy添加对"Pass"Action的支持，可以跳过其他Antrea NetworkPolicy的处理逻辑而将流量转交到Kubernetes NetworkPolicy处理；(#2964, @Dyanngg)
8. 添加在Kubernetes Antrea集群中部署使用Fluentd来收集节点审计日志的指导文档，详细用户文档参考：https://github.com/antrea-io/antrea/tree/main/docs/cookbooks/fluentd；(#2853, @qiyueyao)
9. 添加在AKS集群部署Antrea的指导文档，详情参考：https://github.com/antrea-io/antrea/blob/v1.5.0/docs/aks-installation.md#deploy-antrea-to-an-aks-engine-cluster；(#2963, @jianjuns)
10. 完善NodePortLocal文档；(#3113, @antoninbas)
11. 添加如何在现有集群完成Antrea e2e测试的指导文档；(#3045, @xiaoxiaobaba)

# 变更

1. AntreaProxy新增ProxyExternalIPs参数以增强AntreaProxy对externalIP代理的可配置性，当该参数设置为false时，
AntreaProxy将不再对目的地为LoadBalancer类型Services的ExternalIPs的流量进行负载均衡；(#3130, @antoninbas)
2. 在Traceflow状态添加startTime字段以避免时钟偏差引起的问题；(#2952, @antoninbas)
3. 在'antctl traceflow'命令输出中添加reason字段；(#3175, @Jexf)
4. 只有在AntreaProxy被禁用时才验证serviceCIDR配置；(#2936, @wenyingd)
5. 改进NodeIPAM的配置参数验证；(#3009, @tnqn)
6. 对Antrea原生NetworkPolicy进行更全面的验证；(#3104 #3109, @GraysonWu @tnqn)
7. 更新Antrea Octant插件以支持Octant 0.24并使用Dashboard客户端对Antrea CRD执行CRUD操作； (#2951, @antoninbas)
8. 计算ClusterGroup和AdressGroup时忽略hostNetwork Pod； (#3080, @Dyanngg)
9. 支持使用env参数ALLOW_NO_ENCAP_WITHOUT_ANTREA_PROXY以允许在没有AntreaProxy的情况下以noEncap模式运行Antrea。（#3116，@Jexf @WenzelZ）
10. 网络流量吞吐量计算从使用logstash改变为flow-aggregator以支持更准确的网络流量可见性；（＃2692，@heanlan）
11. 使用"--version"输出版本消息时增加Go版本内容：（＃3182，@antoninbas）
'antrea-agent --version
antrea-agent version v1.5.0-dev-2ee6ad1d.dirty linux/amd64 go1.17.6'；
12. 完善kind-setup.sh脚本和Kind相关文档；（#2937，@antoninbas）
13. 在CI中启用Go benchmark测试；（#3004，@wenqiq）
14. Windows OVS版本升级到2.15.2；（#2996，@lzhecheng）[Windows]
15. [Windows]仅当infra container创建失败时才删除HNSEndpoint；（#2976，@lzhecheng）[Windows]
16. 在Windows上使用containerd作为运行时时，使用OVS端口externalIDs而不是HNSEndpoint来缓存externalIDS；（#2931，@wenyingd）[Windows]
17. 通过使用Windows管理虚拟网络适配器作为OVS内部端口，减少在Windows节点上启动antrea-agent时的网络停机时间；（#3067，@wenyingd）[Windows]

# BugFix

1. 修复Antrea原生NetworkPolicy中Reject Action的错误处理方式； (#3010, @GraysonWu)
2. 修复Antrea NetworkPolicy在AntreaIPAM模式下Reject不生效的问题； (#3003, @GraysonWu)
3. 修复ClusterGroup状态显示不够完善的问题，只有当ClusterGroup的所有子groups创建并有效时才将其状态显示为：groupMembersComputed；(#3030, @Dyanngg)
4. 修复Antrea NetworkPolicy状态在多个AppliedTo的情况下currentNodesRealized和desiredNodesRealized显示不准确的问题； (#3074, @tnqn)
5. 修复拼写错误并改进antrea-network-policy文档中的示例YAML；(#3079, #3092, #3108 @antoninbas @Jexf @tnqn)
6. 使用string set而非string list以修复删除Antrea NetworkPolicy时重复删除未被引用的AddressGroups的问题； (#3136, @Jexf)
7. 增加重试以增强更新NetworkPolicy状态操作的鲁棒性；(#3134, @Jexf)
8. 修复'antctl supportbundle'输出文件中NetworkPolicy相关压缩文件缺失的问题； (#3083, @antoninbas)
9. 使用Go1.17编译和发布Antrea相关二进制文件； (#3007, @antoninbas)
10. 修复Antrea配置IP地址时内核自动配置的网关路由在agent重启时消失的问题；(#3190, @antoninbas)
11. 修复Window上infra container判断的参数错误，该问题会导致重加载HNS Endpoint时的错误；(#3089, @XinShuYang)[Windows]
12. 修复Windows上的网关接口MTU配置错误；(#3043, @[lzhecheng]) [Windows]
13. 通过在VMSwitch命令中明确指定主机名来修复Windows上antrea-agent的初始化错误。(#3169, @XinShuYang) [Windows]

# Contributors

https://github.com/annakhm    
https://github.com/antoninbas    
https://github.com/aravindakidambi    
https://github.com/arunvelayutham    
https://github.com/bangqipropel    
https://github.com/ceclinux    
https://github.com/Dyanngg    
https://github.com/gran-vmv    
https://github.com/heanlan    
https://github.com/hjiajing    
https://github.com/jianjuns    
https://github.com/Jexf    
https://github.com/luolanzone    
https://github.com/lzhecheng    
https://github.com/qiyueyao    
https://github.com/Shengkai2000    
https://github.com/suwang48404    
https://github.com/tnqn    
https://github.com/wenqiq    
https://github.com/wenyingd    
https://github.com/WenzelZ    
https://github.com/xiaoxiaobaba    
https://github.com/XinShuYang    
https://github.com/yanjunz97    

