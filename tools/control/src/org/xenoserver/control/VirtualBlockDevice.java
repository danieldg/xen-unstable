/*
 * VirtualBlockDevice.java
 * 03.03.27 aho creation
 */

package org.xenoserver.control;

import java.io.PrintWriter;

public class VirtualBlockDevice {
  String key;
  int domain;
  int vbdnum;
  Mode mode; /* rw or ro */

  String dump(boolean title) {
    StringBuffer sb = new StringBuffer();

    if (title) {
      sb.append("  key         dom vbd mode\n");
    } else {
      sb.append(
        "  "
          + key
          + "  "
          + Library.format(domain, 3, 0)
          + " "
          + Library.format(vbdnum, 3, 0)
          + " "
          + mode.toString()
          + "\n");
    }

    return sb.toString();
  }

  void dump_xml(PrintWriter out) {
    out.println("  <virtual_block_device>");
    out.println("    <key>" + key + "</key>");
    out.println("    <domain>" + domain + "</domain>");
    out.println("    <vbdnum>" + vbdnum + "</vbdnum>");
    out.println("    <mode>" + mode + "</mode>");
    out.println("  </virtual_block_device>");
  }

  public String getKey() {
    return key;
  }

  public int getDomain() {
    return domain;
  }

  public int getVBDNum() {
    return vbdnum;
  }

  public Mode getMode() {
    return mode;
  }
}
