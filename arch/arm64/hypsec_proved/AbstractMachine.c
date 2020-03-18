#include "hypsec.h"
#include "hacl-20/Hacl_Ed25519.h"
#include "hacl-20/Hacl_AES.h"

void __hyp_text v_panic(void) {
	//__hyp_panic();
	u32 vmid = get_cur_vmid();
	u32 vcpuid = get_cur_vcpu_id();
	if (vmid) {
		print_string("\rvm\n");
		printhex_ul(get_shadow_ctxt(vmid, vcpuid, V_PC));
	} else {
		print_string("\rhost\n");
		printhex_ul(read_sysreg(elr_el2));
	}
	printhex_ul(ESR_ELx_EC(read_sysreg(esr_el2)));
}

void __hyp_text clear_phys_mem(u64 pfn) {
    el2_memset((void *)kern_hyp_va(pfn << PAGE_SHIFT), 0, PAGE_SIZE);
}

u64 __hyp_text get_exception_vector(u64 pstate) {
    // TODO
	return 0;
}

uint8_t* __hyp_text get_vm_public_key(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].public_key;
}

void __hyp_text set_vm_public_key(u32 vmid) {
    unsigned char *public_key_hex = "2ef2440a2b5766436353d07705b602bfab55526831460acb94798241f2104f3a";
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_hex2bin(el2_data->vm_info[vmid].public_key, public_key_hex, 32);
}

uint8_t* __hyp_text get_vm_load_signature(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].signature;
}

void __hyp_text set_vm_load_signature(u32 vmid, u32 load_idx) {
    unsigned char *signature_hex = "35e9848eb618e7150566716662b2f7d8944f0a4e8582ddeb2b209d2bae6b63d5f51ebf1dc54742227e45f7bbb9d4ba1d1f83b52b87a4ce99180aa9a548e7dd05";
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_hex2bin(el2_data->vm_info[vmid].load_info[load_idx].signature,
		signature_hex, 64);
}

//make sure we only use get_int_ctxt to access general purposes regs
void __hyp_text clear_shadow_gp_regs(u32 vmid, u32 vcpuid) {
	struct el2_data *el2_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_memset(el2_data->shadow_vcpu_ctxt[offset].regs,
			0, sizeof(struct kvm_regs));
}

void __hyp_text int_to_shadow_fp_regs(u32 vmid, u32 vcpuid) {

}

void __hyp_text set_per_cpu(int vmid, int vcpu_id)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int pcpuid = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	el2_data->per_cpu_data[pcpuid].vmid = vmid;
	el2_data->per_cpu_data[pcpuid].vcpu_id = vcpu_id;
};

void __hyp_text clear_phys_page(unsigned long pfn)
{
	unsigned long addr = __el2_va(pfn << PAGE_SHIFT);
	el2_memset((void *)addr, 0, PAGE_SIZE);
}

u32 __hyp_text verify_image(u32 vmid, u32 load_idx, u64 addr) {
    uint8_t* signature;
    uint8_t* public_key;
    int result = 0;
    u64 size;
    uint8_t signature1[64], key[32];

    size = get_vm_load_size(vmid, load_idx);
    public_key = get_vm_public_key(vmid);
    signature = get_vm_load_signature(vmid, load_idx);
    print_string("\rverifying image:\n");
    //printhex_ul(size);
    result = Hacl_Ed25519_verify(public_key, size, (uint8_t *)addr, signature);
    //result = Hacl_Ed25519_verify(key, size, (char *)addr, signature1);
    print_string("\r[result]\n");
    printhex_ul(result);
    return 1;
}

void dump_output(char *str, uint8_t *out, int len)
{
	int i;
	unsigned s = 0;
	printk("%s\n", str);
	for (i = 0; i < len; i++) {
		s = out[i];
		printk("%x", s);
	}
	printk("\n");
}

void __hyp_text dump_output_el2(uint8_t *out, int len)
{
	int i;
	unsigned long s = 0;
	for (i = 0; i < len; i++) {
		s = out[i];
		printhex_ul(s);
	}
}

void __hyp_text test_aes(struct el2_data *el2_data)
{
	uint8_t sbox[256];
	uint8_t input[32] = { 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
	uint8_t out[32], out1[32];

	el2_memset(out, 0, sizeof(uint8_t) * 32);
	el2_memset(out1, 0, sizeof(uint8_t) * 32);
	//dump_output_el2(input, 16);
	dump_output("plain", input, 32);
	AES_encrypt_buffer(out, input, el2_data->key, 32);
	//dump_output_el2(out, 16);
	dump_output("crypt", out, 32);

	el2_memset(sbox, 0, sizeof(uint8_t) * 32);
	AES_decrypt_buffer(out1, out, el2_data->key, 32);
	//dump_output_el2(out1, 16);
	dump_output("decrypt", out1, 32);
}

#if 0
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
#endif
