/*
 * XML.java
 * 03.03.26 aho creation
 */

package org.xenoserver.control;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
 
public class
XML
{
  static Document document = null;

  /*
   * dump partition manager and virtual disk manager state to filename
   */

  public static void
  dump_state (PartitionManager pm,/* VirtualDiskManager vdm,*/ String filename)
  {
    PrintWriter out;

    try
    {
      out = new PrintWriter(new BufferedWriter(new FileWriter(filename)));
    }
    catch (IOException e)
    {
      System.err.println ("XML.dump_state error [" + filename + "]");
      System.err.println (e);
      return;
    }

    out.println("<?xml version=\"1.0\"?>");
    out.println("<vdmanager>");
    pm.dump_xml(out);
    //vdm.dump_xml(out);
    out.println("</vdmanager>");

    out.close();
    return;
  }

  /*
   * load partition manager and virtual disk manager state from filename
   */
  public static void
  load_state (PartitionManager pm, /*VirtualDiskManager vdm,*/ String filename)
  {
    if (document == null)
    {
      load_file (filename);
    }

    XMLHelper.parse(pm, /*vdm,*/ document);
  }

  /*
   * load XML from disk
   */
  static void
  load_file (String filename)
  {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // factory.setNamespaceAware(true);
    // factory.setValidating(true);

    try
    {
      File file = new File(filename);

      DocumentBuilder builder = factory.newDocumentBuilder();
      document = builder.parse(file);
    }
    catch (SAXParseException spe)               /* error generated by parser */
    {
      System.err.println ("xml parser exception on line " + 
			  spe.getLineNumber() + 
			  " for uri " + spe.getSystemId());
      System.err.println (spe.getMessage());

      Exception x = spe;
      if (spe.getException() != null)
	x = spe.getException();
      x.printStackTrace();
      System.exit(1);
    }
    catch (SAXException sxe)
    {
      Exception e = sxe;
      if (sxe.getException() != null)
	e = sxe.getException();
      e.printStackTrace();
      System.exit(1);
    }
    catch (ParserConfigurationException pce)
    {
      pce.printStackTrace();
    }
    catch (FileNotFoundException fnfe)
    {
      System.err.println ("warning: state file not found [" +
			  filename + "]");
    }
    catch (IOException ioe)
    {
      ioe.printStackTrace();
    }
    return;
  }
}
