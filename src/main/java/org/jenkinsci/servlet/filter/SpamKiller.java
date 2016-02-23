package org.jenkinsci.servlet.filter;

import com.atlassian.confluence.user.AuthenticatedUserThreadLocal;
import com.atlassian.plugin.servlet.PluginHttpRequestWrapper;
import com.atlassian.spring.container.ContainerManager;
import com.atlassian.user.EntityException;
import com.atlassian.user.Group;
import com.atlassian.user.GroupManager;
import com.atlassian.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.regex.Pattern;

public class SpamKiller implements Filter {
    private static final Logger log = LoggerFactory.getLogger(SpamKiller.class);

    private final Pattern phoneNumberRegex = Pattern.compile(".*8(?:\\d{2})[ \\*~_\\-.=)]*\\d{3}[ \\*~_.\\-=]*\\d{4}.*");
    private final GroupManager groupManager = (GroupManager) ContainerManager.getComponent("groupManager");

    public void init(FilterConfig filterConfig) throws ServletException {}

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        boolean isSpammer = false;
        User confluenceUser = AuthenticatedUserThreadLocal.getUser();
        try {
            Group spammerGroup = null;
            Group moderatorGroup = null;
            moderatorGroup = groupManager.getGroup("moderators");
            spammerGroup = groupManager.getGroup("spammer");
            if (groupManager.hasMembership(spammerGroup, confluenceUser)) {
                isSpammer = true;
            } else if (hasBannedWord(request.getParameter("title")) || hasBannedWord(request.getParameter("wysiwygcontent"))) {
                isSpammer = !groupManager.hasMembership(moderatorGroup, confluenceUser);
            }
        } catch (EntityException e) {
            log.error("Entity Exception during spam check", e);
        }
        if (isSpammer) {
            log.warn("Spammer detected: {}", confluenceUser.toString());
            HttpSession session = ((PluginHttpRequestWrapper) request).getSession();
            session.invalidate();
            ((HttpServletResponse) response).sendError(500, "Test");
        } else {
            chain.doFilter(request, response);
        }
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