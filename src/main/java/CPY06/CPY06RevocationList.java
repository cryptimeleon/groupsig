package de.upb.crypto.craco.groupsig.CPY06;

import de.upb.crypto.craco.groupsig.interfaces.RevocationList;
import de.upb.crypto.craco.groupsig.interfaces.RevocationListEntry;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Collection;
import java.util.HashMap;
import java.util.Objects;

public class CPY06RevocationList implements RevocationList {

    @Represented(restorer = "id -> entry")
    private HashMap<Integer, CPY06RevocationListEntry> entries;

    public CPY06RevocationList() {
        this.entries = new HashMap<>();
    }

    public CPY06RevocationList(Representation repr, CPY06SignatureScheme scheme) {
        new ReprUtil(this).register(scheme, "entry").deserialize(repr);
    }

    @Override
    public void put (RevocationListEntry e) {
        entries.put(((CPY06RevocationListEntry) e).getIdentity(), (CPY06RevocationListEntry) e);
    }

    @Override
    public CPY06RevocationListEntry get(Integer identity) {
        return entries.get(identity);
    }

    public Boolean containsValueForId(Integer identity) {
        return entries.containsKey(identity);
    }
    
    public Collection<CPY06RevocationListEntry> getValues() {
        return entries.values();
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
        CPY06RevocationList other = (CPY06RevocationList) obj;
        return Objects.equals(entries, other.entries);
    }
}
