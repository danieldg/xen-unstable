package org.xenoserver.cmdline;

import org.xenoserver.control.Command;
import org.xenoserver.control.CommandDestroy;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class ParseDestroy extends CommandParser {
  public void parse(Defaults d, String[] args) throws ParseFailedException, CommandFailedException {
    int domain_id = getIntParameter(args, 'n', 0);
    boolean force = getFlagParameter(args, 'f');

    if (domain_id == 0) {
      throw new ParseFailedException("Expected -n<domain_id>");
    }

    String output = new CommandDestroy(d, domain_id, force).execute();
    if ( output != null )
      System.out.println( output );
  }
  
  public String getName()
  {
    return "destroy";
  }

  public String getUsage()
  {
    return "[-f] [-n<domain_id>]";
  }

  public String getHelpText()
  {
    return
      "Destory the specified domain.  -f forcibly destroys it.";
  }
}
