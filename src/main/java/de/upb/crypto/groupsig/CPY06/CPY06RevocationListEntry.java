package de.upb.crypto.groupsig.CPY06;

import de.upb.crypto.groupsig.common.RevocationListEntry;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;

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
