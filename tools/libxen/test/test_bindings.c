/*
 * Copyright (c) 2006 XenSource, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>
#include <curl/curl.h>

#include "xen_host.h"
#include "xen_sr.h"
#include "xen_vbd.h"
#include "xen_vdi.h"
#include "xen_vm.h"


static void usage()
{
    fprintf(stderr,
"Usage:\n"
"\n"
"    test_bindings <url> <username> <password>\n"
"\n"
"where\n"
"        <url>      is a fragment of the server's URL, e.g. localhost:8005/RPC2;\n"
"        <username> is the username to use at the server; and\n"
"        <password> is the password.\n");

    exit(EXIT_FAILURE);
}


static char *url;


typedef struct
{
    xen_result_func func;
    void *handle;
} xen_comms;


static xen_vm create_new_vm(xen_session *session);
static void print_vm_power_state(xen_session *session, xen_vm vm);


static size_t
write_func(void *ptr, size_t size, size_t nmemb, xen_comms *comms)
{
    size_t n = size * nmemb;
    return comms->func(ptr, n, comms->handle) ? n : 0;
}


static int
call_func(const void *data, size_t len, void *user_handle,
          void *result_handle, xen_result_func result_func)
{
    (void)user_handle;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    xen_comms comms = {
        .func = result_func,
        .handle = result_handle
    };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_MUTE, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &comms);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);

    CURLcode result = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    return result;
}


static void print_error(xen_session *session)
{
    fprintf(stderr, "Error: %d", session->error_description_count);
    for (int i = 0; i < session->error_description_count; i++)
    {
        fprintf(stderr, "%s ", session->error_description[i]);
    }
    fprintf(stderr, "\n");
}


int main(int argc, char **argv)
{
    if (argc != 4)
    {
        usage();
    }

    url = argv[1];
    char *username = argv[2];
    char *password = argv[3];

    xmlInitParser();
    xen_init();
    curl_global_init(CURL_GLOBAL_ALL);

#define CLEANUP                                 \
    do {                                        \
        xen_session_logout(session);            \
        curl_global_cleanup();                  \
        xen_fini();                             \
        xmlCleanupParser();                     \
    } while(0)                                  \

    
    xen_session *session =
        xen_session_login_with_password(call_func, NULL, username, password);

    xen_vm vm;
    if (!xen_vm_get_by_uuid(session, &vm,
                            "00000000-0000-0000-0000-000000000000"))
    {
        print_error(session);
        CLEANUP;
        return 1;
    }

    char *vm_uuid;
    if (!xen_vm_get_uuid(session, &vm_uuid, vm))
    {
        print_error(session);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    char *vm_uuid_bytes;
    if (!xen_uuid_string_to_bytes(vm_uuid, &vm_uuid_bytes))
    {
        fprintf(stderr, "xen_uuid_string_to_bytes failed.\n");
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_vm_record *vm_record;
    if (!xen_vm_get_record(session, &vm_record, vm))
    {
        print_error(session);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_host host;
    if (!xen_session_get_this_host(session, &host))
    {
        print_error(session);
        xen_vm_record_free(vm_record);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    xen_string_string_map *versions;
    if (!xen_host_get_software_version(session, &versions, host))
    {
        print_error(session);
        xen_host_free(host);
        xen_vm_record_free(vm_record);
        xen_uuid_bytes_free(vm_uuid_bytes);
        xen_uuid_free(vm_uuid);
        xen_vm_free(vm);
        CLEANUP;
        return 1;
    }

    printf("%s.\n", vm_uuid);

    fprintf(stderr, "In bytes, the VM UUID is ");
    for (int i = 0; i < 15; i++)
    {
        fprintf(stderr, "%x, ", (unsigned int)vm_uuid_bytes[i]);
    }
    fprintf(stderr, "%x.\n", (unsigned int)vm_uuid_bytes[15]);

    printf("%zd.\n", versions->size);

    for (size_t i = 0; i < versions->size; i++)
    {
        printf("%s -> %s.\n", versions->contents[i].key,
               versions->contents[i].val);
    }

    printf("%s.\n", vm_record->uuid);

    printf("Resident on %s.\n", (char *)vm_record->resident_on->u.handle);

    printf("%s.\n", xen_vm_power_state_to_string(vm_record->power_state));

    for (size_t i = 0; i < vm_record->vcpus_utilisation->size; i++)
    {
        printf("%"PRId64" -> %lf.\n",
               vm_record->vcpus_utilisation->contents[i].key,
               vm_record->vcpus_utilisation->contents[i].val);
    }

    xen_uuid_bytes_free(vm_uuid_bytes);
    xen_uuid_free(vm_uuid);
    xen_vm_free(vm);

    xen_vm_record_free(vm_record);

    xen_host_free(host);
    xen_string_string_map_free(versions);


    xen_vm new_vm = create_new_vm(session);
    if (!session->ok)
    {
        /* Error has been logged, just clean up. */
        CLEANUP;
        return 1;
    }

    print_vm_power_state(session, new_vm);
    if (!session->ok)
    {
        /* Error has been logged, just clean up. */
        xen_vm_free(new_vm);
        CLEANUP;
        return 1;
    }

    xen_vm_free(new_vm);
    CLEANUP;

    return 0;
}


/**
 * Creation of a new VM, using the Named Parameters idiom.  Allocate the
 * xen_vm_record here, but the sets through the library.  Either
 * allocation patterns can be used, as long as the allocation and free are
 * paired correctly.
 */
static xen_vm create_new_vm(xen_session *session)
{
    xen_cpu_feature_set *empty_cpu_feature_set =
        xen_cpu_feature_set_alloc(0);

    xen_cpu_feature_set *force_off_cpu_feature_set =
        xen_cpu_feature_set_alloc(1);
    force_off_cpu_feature_set->contents[0] = XEN_CPU_FEATURE_MMX;

    xen_vm_record vm_record =
        {
            .name_label = "NewVM",
            .name_description = "New VM Description",
            .user_version = 1,
            .is_a_template = false,
            .memory_static_max = 256,
            .memory_dynamic_max = 256,
            .memory_dynamic_min = 128,
            .memory_static_min = 128,
            .vcpus_policy = "credit",
            .vcpus_params = "",
            .vcpus_number = 2,
            .vcpus_features_required = empty_cpu_feature_set,
            .vcpus_features_can_use = empty_cpu_feature_set,
            .vcpus_features_force_on = empty_cpu_feature_set,
            .vcpus_features_force_off = force_off_cpu_feature_set,
            .actions_after_shutdown = XEN_ON_NORMAL_EXIT_DESTROY,
            .actions_after_reboot = XEN_ON_NORMAL_EXIT_RESTART,
            .actions_after_suspend = XEN_ON_NORMAL_EXIT_DESTROY,
            .actions_after_crash = XEN_ON_CRASH_BEHAVIOUR_PRESERVE,
            .hvm_boot = "",
            .pv_bootloader = "pygrub",
            .pv_kernel = "/boot/vmlinuz-2.6.16.33-xen",
            .pv_ramdisk = "",
            .pv_args = "",
            .pv_bootloader_args = ""
        };


    xen_vm vm;
    xen_vm_create(session, &vm, &vm_record);

    xen_cpu_feature_set_free(empty_cpu_feature_set);
    xen_cpu_feature_set_free(force_off_cpu_feature_set);

    if (!session->ok)
    {
        fprintf(stderr, "VM creation failed.\n");
        print_error(session);
        return NULL;
    }


    /*
     * Create a new disk for the new VM.
     */
    xen_sr_set *srs;
    if (!xen_sr_get_by_name_label(session, &srs, "Local") ||
        srs->size < 1)
    {
        fprintf(stderr, "SR lookup failed.\n");
        print_error(session);
        xen_vm_free(vm);
        return NULL;
    }

    xen_sr_record_opt sr_record =
        {
            .u.handle = srs->contents[0]
        };
    xen_vdi_record vdi0_record =
        {
            .name_label = "MyRootFS",
            .name_description = "MyRootFS description",
            .sr = &sr_record,
            .virtual_size = (1 << 21),  // 1GiB / 512 bytes/sector
            .sector_size = 512,
            .type = XEN_VDI_TYPE_SYSTEM,
            .sharable = false,
            .read_only = false
        };
    
    xen_vdi vdi0;
    if (!xen_vdi_create(session, &vdi0, &vdi0_record))
    {
        fprintf(stderr, "VDI creation failed.\n");
        print_error(session);

        xen_sr_set_free(srs);
        xen_vm_free(vm);
        return NULL;
    }


    xen_vm_record_opt vm_record_opt =
        {
            .u.handle = vm
        };
    xen_vdi_record_opt vdi0_record_opt =
        {
            .u.handle = vdi0
        };
    xen_vbd_record vbd0_record =
        {
            .vm = &vm_record_opt,
            .vdi = &vdi0_record_opt,
            .device = "xvda1",
            .mode = XEN_VBD_MODE_RW
        };

    xen_vbd vbd0;
    if (!xen_vbd_create(session, &vbd0, &vbd0_record))
    {
        fprintf(stderr, "VBD creation failed.\n");
        print_error(session);

        xen_vdi_free(vdi0);
        xen_sr_set_free(srs);
        xen_vm_free(vm);
        return NULL;
    }

    char *vm_uuid;
    char *vdi0_uuid;
    char *vbd0_uuid;

    xen_vm_get_uuid(session,  &vm_uuid,   vm);
    xen_vdi_get_uuid(session, &vdi0_uuid, vdi0);
    xen_vbd_get_uuid(session, &vbd0_uuid, vbd0); 

    if (!session->ok)
    {
        fprintf(stderr, "get_uuid call failed.\n");
        print_error(session);

        xen_uuid_free(vm_uuid);
        xen_uuid_free(vdi0_uuid);
        xen_uuid_free(vbd0_uuid);
        xen_vbd_free(vbd0);
        xen_vdi_free(vdi0);
        xen_sr_set_free(srs);
        xen_vm_free(vm);
        return NULL;
    }

    fprintf(stderr,
            "Created a new VM, with UUID %s, VDI UUID %s, and VBD UUID %s.\n",
            vm_uuid, vdi0_uuid, vbd0_uuid);

    xen_uuid_free(vm_uuid);
    xen_uuid_free(vdi0_uuid);
    xen_uuid_free(vbd0_uuid);
    xen_vbd_free(vbd0);
    xen_vdi_free(vdi0);
    xen_sr_set_free(srs);

    return vm;
}


/**
 * Print the power state for the given VM.
 */
static void print_vm_power_state(xen_session *session, xen_vm vm)
{
    char *vm_uuid;
    enum xen_vm_power_state power_state;

    if (!xen_vm_get_uuid(session, &vm_uuid, vm))
    {
        print_error(session);
        return;
    }

    if (!xen_vm_get_power_state(session, &power_state, vm))
    {
        xen_uuid_free(vm_uuid);
        print_error(session);
        return;
    }

    printf("VM %s power state is %s.\n", vm_uuid,
           xen_vm_power_state_to_string(power_state));

    xen_uuid_free(vm_uuid);
}
