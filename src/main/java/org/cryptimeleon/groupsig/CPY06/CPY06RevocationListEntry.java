package org.cryptimeleon.groupsig.CPY06;

import org.cryptimeleon.groupsig.common.RevocationListEntry;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

public class CPY06RevocationListEntry implements RevocationListEntry {

    @Represented
    private Integer identity;

    @Represented(restorer = "G1")
    private GroupElement C;

    public CPY06RevocationListEntry(Integer identity, GroupElement c) {
        this.identity = identity;
        C = c;
    }

    public CPY06RevocationListEntry(Representation repr, Group g1) {
        new ReprUtil(this).register(g1, "G1").deserialize(repr);
    }

    public Integer getIdentity() {
        return identity;
    }

    public GroupElement getC() {
        return C;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
