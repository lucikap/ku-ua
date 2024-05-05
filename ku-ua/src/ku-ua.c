#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/tcp.h>

static struct nf_hook_ops nfho;
static unsigned int tcp_packet_with_ua_count = 0;
static char *ua_field = "User-Agent";
static char *predefined_ua = "%25E5%25B8%2583%25E9%25B2%2581%25E5%258D%25A1%25E9%2597%25A8";
static int predefined_ua_len;
module_param(predefined_ua, charp, 0644);

static void compute_tcp_checksum(struct sk_buff *skb);

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    unsigned char *payload;
    int payload_len;
    char *ua_pos;
    char *ua_end;
    //strreplace(predefined_ua, '#', ' ');
    predefined_ua_len = strlen(predefined_ua);
    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);

    if (ip_header->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcp_header = tcp_hdr(skb);

    payload = skb->data + (ip_header->ihl * 4) + (tcp_header->doff * 4);
    payload_len = skb->len - (ip_header->ihl * 4) - (tcp_header->doff * 4);

    ua_pos = strstr(payload, ua_field);
    if (ua_pos) {
        ua_pos += strlen(ua_field) + 2;
        ua_end = strchr(ua_pos, '\r');
        if (ua_end) {
            int ua_len = ua_end - ua_pos;
            if (strstr(ua_pos, "Lin") != NULL || strstr(ua_pos, "Win") != NULL || 
                 strstr(ua_pos, "OS") != NULL || strstr(ua_pos, "And") != NULL) {
                memset(ua_pos, ' ', ua_len);
                if (ua_len >= predefined_ua_len) {
                    memcpy(ua_pos, predefined_ua, predefined_ua_len);
                } else {
                    memcpy(ua_pos, predefined_ua, ua_len);
                }
                compute_tcp_checksum(skb);
                tcp_packet_with_ua_count++;
                if (tcp_packet_with_ua_count % 500 == 0) {
                    printk(KERN_INFO "[ku-ua]已累计处理 %u 个包\n", tcp_packet_with_ua_count);
                }
            }
        }
    }
    return NF_ACCEPT;
}

//重新计算校验和
static void compute_tcp_checksum(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);

    tcph->check = 0;
    skb->csum = skb_checksum(skb, iph->ihl * 4, skb->len - iph->ihl * 4, 0);
    tcph->check = tcp_v4_check(skb->len - (iph->ihl * 4), iph->saddr, iph->daddr, skb->csum);
}

static int __init kuua_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[ku-ua]模块已加载\n");
    printk(KERN_INFO "[ku-ua]作者：Brukamen\n");
    printk(KERN_INFO "[ku-ua]邮箱：169296793@qq.com\n");
    printk(KERN_INFO "[ku-ua]交流群（QQ）：555201601\n");
    printk(KERN_INFO "[ku-ua]源码仓库：https://github.com/lucikap/ku-ua\n");
    printk(KERN_INFO "[ku-ua]模块说明：\n");
    printk(KERN_INFO "[ku-ua]此模块用于修改含有User-Agent的包\n");
    printk(KERN_INFO "[ku-ua]此模块遵循开源许可协议《GPL》（商业软件绕开）既：不允许修改后和衍生的代码做为闭源的商业软件发布和销售\n");
    printk(KERN_INFO "[ku-ua]免责声明：\n");
    printk(KERN_INFO "[ku-ua]1、此模块尚在测试阶段，作者不对此模块的稳定性、实用性做任何保证！！\n");
    printk(KERN_INFO "[ku-ua]2、由于使用此模块对系统或硬件产生的不可逆破坏与作者无关！！\n");
    printk(KERN_INFO "[ku-ua]3、开源软件仅用于学习技术为目的，如果将此软件及其衍生代码用于违法目的导致的不良后果由使用者自行承担！！\n");
    return 0;
}

static void __exit kuua_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[ku-ua]模块已卸载\n");
    printk(KERN_INFO "[ku-ua]本次启用总共修改了：%u 个含User-Agent的包\n", tcp_packet_with_ua_count);
}

module_init(kuua_init);
module_exit(kuua_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Brukamen");
