
import string, re, os

def blkdev_name_to_number(name):
    """Take the given textual block-device name (e.g., '/dev/sda1',
    'hda') and return the device number used by the OS. """

    if not re.match( '/dev/', name ):
        name = '/dev/' + name
        
    return os.stat(name).st_rdev


# lookup_blkdev_partn_info( '/dev/sda3' )
def lookup_raw_partn(partition):
    """Take the given block-device name (e.g., '/dev/sda1', 'hda')
    and return a information tuple ( partn-dev, disc-dev, start-sect,
    nr-sects, type )
        partn-dev:  Device number of the given partition
        disc-dev:   Device number of the disc containing the partition
        start-sect: Index of first sector of the partition
        nr-sects:   Number of sectors comprising this partition
        type:       'Disk' or identifying name for partition type
    """

    if not re.match( '/dev/', partition ):
        partition = '/dev/' + partition

    drive = re.split( '[0-9]', partition )[0]

    if drive == partition:
        fd = os.popen( '/sbin/sfdisk -s ' + drive + ' 2>/dev/null' )
        line = fd.readline()
        if line:
            return [( blkdev_name_to_number(drive),
                     0,
                     string.atol(line) * 2,
                     'Disk' )]
        return None

    # determine position on disk
    fd = os.popen( '/sbin/sfdisk -d ' + drive + ' 2>/dev/null' )

    #['/dev/sda3 : start= 16948575, size=16836120, Id=83, bootable\012']
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^' + partition + '\s*: start=\s*([0-9]+), ' +
                       'size=\s*([0-9]+), Id=\s*(\S+).*$', line)
        if m:
            return [( blkdev_name_to_number(drive),
                     string.atol(m.group(1)),
                     string.atol(m.group(2)),
                     m.group(3) )]
    return None

def lookup_disk_uname( uname ):
    ( type, d_name ) = string.split( uname, ':' )

    if type == "phy":
	segments = lookup_raw_partn( d_name )
    elif type == "vd":
	segments = lookup_vd( d_name )

    return segments

def get_current_ipaddr(dev='eth0'):
    """Return a string containing the primary IP address for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^\s+inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipmask(dev='eth0'):
    """Return a string containing the primary IP netmask for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^.+Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipgw(dev='eth0'):
    """Return a string containing the IP gateway for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/route -n' )
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^\S+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' +
                       '\s+\S+\s+\S*G.*' + dev + '.*', line )
        if m:
            return m.group(1)
    return None

def setup_vfr_rules_for_vif(dom,vif,addr):
    """Takes a tuple ( domain-id, vif-id, ip-addr ), where the ip-addr
    is expressed as a textual dotted quad, and set up appropriate routing
    rules in Xen. No return value.
    """
    fd = os.open( '/proc/xeno/vfr', os.O_WRONLY )
    if ( re.search( '169\.254', addr) ):
        os.write( fd, 'ADD ACCEPT srcaddr=' + addr +
                  ' srcaddrmask=255.255.255.255' +
                  ' srcdom=' + str(dom) + ' srcidx=' + str(vif) +
                  ' dstdom=0 dstidx=0 proto=any\n' )
    else:
        os.write( fd, 'ADD ACCEPT srcaddr=' + addr +
                  ' srcaddrmask=255.255.255.255' +
                  ' srcdom=' + str(dom) + ' srcidx=' + str(vif) +
                  ' dst=PHYS proto=any\n' )
    os.write( fd, 'ADD ACCEPT dstaddr=' + addr +
              ' dstaddrmask=255.255.255.255' +
              ' src=ANY' +
              ' dstdom=' + str(dom) + ' dstidx=' + str(vif) +
              ' proto=any\n' )
    os.close( fd )
    return None

def add_offset_to_ip( ip, off ):
    l = string.split(ip,'.')
    a = ( (string.atoi(l[0])<<24) | (string.atoi(l[1])<<16) | 
	  (string.atoi(l[2])<<8)  | string.atoi(l[3]) ) + off
    
    return '%d.%d.%d.%d' % ( ((a>>24)&0xff), ((a>>16)&0xff),
			     ((a>>8)&0xff), (a&0xff) )

