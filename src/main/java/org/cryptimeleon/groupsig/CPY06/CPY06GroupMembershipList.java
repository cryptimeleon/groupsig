package org.cryptimeleon.groupsig.CPY06;

import org.cryptimeleon.groupsig.common.GMLEntry;
import org.cryptimeleon.groupsig.common.GroupMembershipList;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.HashMap;
import java.util.Objects;

public class CPY06GroupMembershipList implements GroupMembershipList {

    @Represented(restorer = "id -> entry")
    private HashMap<Integer, CPY06GMLEntry> entries;

    public CPY06GroupMembershipList() {
        this.entries = new HashMap<>();
    }

    public CPY06GroupMembershipList(Representation repr, CPY06SignatureScheme scheme) {
        new ReprUtil(this).register(scheme, "entry").deserialize(repr);
    }

    @Override
    public void put(GMLEntry e) {
        entries.put(((CPY06GMLEntry) e).getIdentity(), (CPY06GMLEntry) e);
    }

    @Override
    public CPY06GMLEntry get(Integer id) {
        return entries.get(id);
    }

    public Integer findUserIdFor(GroupElement A) {
        for (CPY06GMLEntry e : entries.values()) {
            if (A.equals(e.getA()))
                return e.getIdentity();
        }
        throw new IllegalStateException("User does not exist.");
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        return entries.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06GroupMembershipList other = (CPY06GroupMembershipList) obj;
        return Objects.equals(entries, other.entries);
    }
}
