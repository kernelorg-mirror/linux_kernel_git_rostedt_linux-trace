// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025, Google LLC, Steven Rostedt
 */
#include <linux/platform_device.h>
#include <linux/memory_hotplug.h>
#include <linux/libnvdimm.h>
#include <linux/module.h>
#include <linux/numa.h>

static char *mem_name;
module_param_named(mem_name, mem_name, charp, 0400);
MODULE_PARM_DESC(mem_name, "name of kernel param that holds addr");

static void reserve_mem_remove(struct platform_device *pdev)
{
	struct nvdimm_bus *nvdimm_bus = platform_get_drvdata(pdev);

	nvdimm_bus_unregister(nvdimm_bus);
}

static int walk_ram(struct resource *res, void *data)
{
	struct nd_region_desc ndr_desc;
	struct nvdimm_bus *nvdimm_bus = data;
	int nid;

	memset(&ndr_desc, 0, sizeof(ndr_desc));
	nid = phys_to_target_node(res->start);
	ndr_desc.res = res;
	ndr_desc.numa_node = numa_map_to_online_node(nid);
	ndr_desc.target_node = nid;
	set_bit(ND_REGION_PAGEMAP, &ndr_desc.flags);
	trace_printk("ND_RES=%px (%s) START:%lx END:%lx\n", ndr_desc.res, ndr_desc.res->name,
	       (long)ndr_desc.res->start, (long)ndr_desc.res->end);
	if (!nvdimm_pmem_region_create(nvdimm_bus, &ndr_desc))
		return -ENXIO;
	return 1;
}

static int reserve_mem_probe(struct platform_device *pdev)
{
	static struct nvdimm_bus_descriptor nd_desc;
	struct device *dev = &pdev->dev;
	struct nvdimm_bus *nvdimm_bus;
	phys_addr_t start;
	phys_addr_t size;
	unsigned long end;
	int rc = -ENXIO;

	trace_printk("Here: mem_name=%s\n", mem_name ?: "(NULL)");
	if (!mem_name)
		return rc;

	if (!reserve_mem_find_by_name(mem_name, &start, &size)) {
		dev_err(dev, "Reserved memory '%s' not found\n", mem_name);
		return rc;
	}

	end = start + size - 1;

	nd_desc.provider_name = "reserve_mem";
	nd_desc.module = THIS_MODULE;
	nvdimm_bus = nvdimm_bus_register(dev, &nd_desc);
	if (!nvdimm_bus)
		goto err;
	platform_set_drvdata(pdev, nvdimm_bus);

	trace_printk("LOOK FOR %lx to %lx\n", (long)start, end);

	rc = walk_iomem_res_desc(0, IORESOURCE_SYSTEM_RAM,
				 start, end, nvdimm_bus, walk_ram);
	if (rc < 0)
		goto err;
	
	return 0;
err:
	nvdimm_bus_unregister(nvdimm_bus);
	dev_err(dev, "failed to register reserved memory '%s'\n", mem_name);
	return rc;
}

static struct platform_driver reserve_mem_driver = {
	.probe = reserve_mem_probe,
	.remove = reserve_mem_remove,
	.driver = {
		.name = "reserve_pmem",
	},
};

module_platform_driver(reserve_mem_driver);

MODULE_ALIAS("platform:reserve_mem*");
MODULE_DESCRIPTION("NVDIMM support for reserve_mem kernel parameter");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Steven Rostedt");
