#include "hypsec.h"

/*
 * VMPower
 */

void set_vm_poweroff(u32 vmid)
{
	acquire_lock_vm(vmid);
	set_vm_power(vmid, 0U);
	release_lock_vm(vmid);
}

//TODO: can we simplify this?
u32 get_vm_poweron(u32 vmid)
{
	u32 ret;
	acquire_lock_vm(vmid);
	ret = get_vm_power(vmid);
	release_lock_vm(vmid);
	return ret;
}
