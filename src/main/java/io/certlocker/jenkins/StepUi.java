package io.certlocker.jenkins;

import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;

final class StepUi {
    static ListBoxModel servers() {
        Jenkins.get().checkPermission(Jenkins.READ);
        var items = new ListBoxModel();
        for (var server : CertLockerConfiguration.get().getServers()) {
            items.add(server.getName(), server.getName());
        }
        return items;
    }
}
