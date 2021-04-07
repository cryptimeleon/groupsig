package org.cryptimeleon.groupsig.common.protocol;

import org.cryptimeleon.craco.protocols.TwoPartyProtocolInstance;

public interface IssuingProtocolInstance extends TwoPartyProtocolInstance {

    @Override
    IssuingProtocol getProtocol();
}
