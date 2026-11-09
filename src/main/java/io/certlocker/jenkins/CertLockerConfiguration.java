package io.certlocker.jenkins;

import hudson.Extension;
import hudson.model.PersistentDescriptor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;

@Extension
public final class CertLockerConfiguration extends GlobalConfiguration implements PersistentDescriptor {
    private List<CertLockerServer> servers = new ArrayList<>();

    public CertLockerConfiguration() {
        load();
    }

    public static CertLockerConfiguration get() {
        return GlobalConfiguration.all().get(CertLockerConfiguration.class);
    }

    @Override
    public String getDisplayName() {
        return "CertLocker";
    }

    public List<CertLockerServer> getServers() {
        return List.copyOf(servers);
    }

    @DataBoundSetter
    public void setServers(List<CertLockerServer> servers) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        List<CertLockerServer> copy = servers == null ? List.of() : List.copyOf(servers);
        var names = new HashSet<String>();
        for (var server : copy) {
            if (!names.add(server.getName())) {
                throw new IllegalArgumentException("CertLocker server names must be unique");
            }
            CertLockerServer.endpoint(server.getUrl());
        }
        this.servers = new ArrayList<>(copy);
        save();
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws FormException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        setServers(req.bindJSONToList(CertLockerServer.class, json.get("servers")));
        return true;
    }

    CertLockerServer findServer(String name) {
        return servers.stream()
                .filter(s -> s.getName().equals(name))
                .findFirst()
                .orElse(null);
    }
}
