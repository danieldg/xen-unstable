package org.xenoserver.cmdline;

import org.xenoserver.control.Command;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandList;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Domain;

public class ParseList extends CommandParser {

  public void parse(Defaults d, String[] args) throws ParseFailedException, CommandFailedException {
    CommandList list = new CommandList(d);
    String output = list.execute();
    if ( output != null )
      System.out.println( output );
    Domain[] domains = list.domains();

    for (int loop = 0; loop < domains.length; loop++)
    {
      System.out.println ("id: " + domains[loop].id + 
        " (" + domains[loop].name+ ")");
      System.out.println ("  processor: " + domains[loop].processor);
      System.out.println ("  has cpu: " + domains[loop].cpu);
      System.out.println ("  state: " + domains[loop].nstate + " " +
        domains[loop].state);
      System.out.println ("  mcu advance: " + domains[loop].mcu);
      System.out.println ("  total pages: " + domains[loop].pages);
    }
  }

  public String getName()
  {
    return "list";
  }

  public String getUsage()
  {
    return "";
  }

  public String getHelpText()
  {
    return
      "List domain information";
  }
}
