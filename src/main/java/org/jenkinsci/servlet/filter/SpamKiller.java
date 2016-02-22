package org.jenkinsci.servlet.filter;

import com.atlassian.plugin.servlet.PluginHttpRequestWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final Logger log = LoggerFactory.getLogger(SpamKiller.class);
    private final Pattern phoneNumberRegex = Pattern.compile(".*8(?:\\d{2})[ \\*~_\\-.=)]*\\d{3}[ \\*~_.\\-=]*\\d{4}.*");

    public void init(FilterConfig filterConfig) throws ServletException {}

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String title = request.getParameter("title");
        if(title != null) {
            if (hasBannedWord(title, request.getParameter("wysiwygcontent"),
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
            )) {
                HttpSession session = ((PluginHttpRequestWrapper) request).getSession();
                String username = ((PluginHttpRequestWrapper) request).getSession().getAttribute("seraph_defaultauthenticator_user").toString();
                log.error("Spam page detected. title={}, username={}", title, username);
                session.invalidate();
                throw new ServletException("This content has been determined to be spam.");
            }
        }
        chain.doFilter(request, response);
    }

    private boolean hasBannedWord(String title, String content, String... bannedWords) {
        if(hasPhoneNumber(title, content)) {
            return true;
        }
        for (String bannedWord : bannedWords) {
            if (title != null && title.toLowerCase().contains(bannedWord) ||
                content != null && content.toLowerCase().contains(bannedWord)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasPhoneNumber(String title, String content) {
        return phoneNumberRegex.matcher(title).matches() || phoneNumberRegex.matcher(content).matches();
    }

}