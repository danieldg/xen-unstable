package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandDomainDestroy;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class ParseDomainDestroy extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        int domain_id = getIntParameter(args, 'n', d.domainNumber);
        boolean force = getFlagParameter(args, 'f');

        if (domain_id == 0) {
            throw new ParseFailedException("Expected -n<domain_id>");
        }

        String output = new CommandDomainDestroy(d, domain_id, force).execute();
        if (output != null) {
            System.out.println(output);
        }
    }

    public String getName() {
        return "destroy";
    }

    public String getUsage() {
        return "[-n<domain_id>] [-f]";
    }

    public String getHelpText() {
        return "Destroy the specified domain.  -f forcibly destroys it.";
    }
}
