#include "hypervisor-ifs/dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_stop";

static int stop_domain(int id)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_STOPDOMAIN;
    op.u.meminfo.domain = id;

    err = do_dom0_op(&op);

    return (err < 0) ? -1 : 0;
}    

int main(int argc, char **argv)
{
    int rc;

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc != 2 ) 
    {
        fprintf(stderr, "Usage: %s <domain-id>\n", argv0);
        return 1;
    }

    rc = stop_domain(atol(argv[1]));

    return (rc != 0) ? 1 : 0;
}
