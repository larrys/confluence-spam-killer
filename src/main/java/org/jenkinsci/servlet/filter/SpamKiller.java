package org.jenkinsci.servlet.filter;

import com.atlassian.plugin.servlet.PluginHttpRequestWrapper;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.regex.Pattern;

public class SpamKiller implements Filter {
    private final Pattern phoneNumberRegex = Pattern.compile(".*8(?:\\d{2})[ \\*~_\\-.=)]*\\d{3}[ \\*~_.\\-=]*\\d{4}.*");


    public void init(FilterConfig filterConfig) throws ServletException {}

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (hasBannedWord(request.getParameter("title")) || hasBannedWord(request.getParameter("wysiwygcontent"))) {
            HttpSession session = ((PluginHttpRequestWrapper) request).getSession();
            session.invalidate();
            throw new ServletException("This content has been determined to be spam.");
        }
        chain.doFilter(request, response);
    }

    private boolean hasBannedWord(String content) {
        String[] bannedWords = {
            "printer support",
            "q.u.i.c.k.b.o.o.k.s",
            "quickbook",
            "quicken",
            "s.u.p.p.o.r.t.",
            "Samsung Printer",
            "solahartcenter.com",
            "support phone",
            "toll free",
            "www.service-solahart.com"
        };
        if (content != null) {
            if (phoneNumberRegex.matcher(content).matches()) {
                return true;
            }
            for (String bannedWord : bannedWords) {
                if (content.toLowerCase().contains(bannedWord)) {
                    return true;
                }
            }
        }
        return false;
    }

}