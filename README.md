![Build Status](https://github.com/cryptimeleon/predenc/workflows/Development%20Java%20CI/badge.svg)
![Build Status](https://github.com/cryptimeleon/predenc/workflows/Release%20Java%20CI/badge.svg)
## Cryptimeleon Groupsig

The Groupsig library offers interfaces and tests useful for implementing group signatures as well as example implementations in Java 8.
The interfaces have largely been derived from [DiaArrRod15].

## Security Disclaimer
**WARNING: This library is meant to be used for prototyping and as a research tool *only*. It has not been sufficiently vetted for use in security-critical production environments. All implementations are to be considered experimental.**


## Implementations
We are currently working on implementing the traceable group signature from [ChoParYun06].

## Quickstart

### Installation

At the moment, Groupsig does not have a release version and needs to be installed by cloning this repository, building the project, and publishing it to your local Maven repository.

To do this, run the following commands:

```
git clone git@github.com:cryptimeleon/groupsig.git
cd groupsig
./gradlew build
./gradlew publishToMavenLocal
```

Once you have done this, you can add it as a dependency. You will need to enable dependency resolution for your local Maven repository as well.

### Adding Dependency For Maven
To add the newest Groupsig version as a dependency, add this to your project's POM:

```xml
<dependency>
    <groupId>org.cryptimeleon</groupId>
    <artifactId>groupsig</artifactId>
    <version>0.0.1</version>
</dependency>
```

### Adding Dependency For Gradle

Groupsig is not published via an online repository.
You will need to use the version from your local Maven repository.
Therefore, you need to add `mavenLocal()` to the `repositories` section of your project's `build.gradle` file.
Then, add `implementation group: 'org.cryptimeleon', name: 'groupsig', version: '0.0.1'` to the `dependencies` section of your `build.gradle` file.

For example:

```groovy
repositories {
    mavenLocal()
}

dependencies {
    implementation group: 'org.cryptimeleon', name: 'groupsig', version: '0.0.1'
}
```

### Tutorials
Groupsig uses the mathematical facilities of our [Math library](https://github.com/cryptimeleon/math).
Therefore, we recommend you go through our [short Math tutorial](https://cryptimeleon.github.io/getting-started/5-minute-tutorial.html) to get started.

## Miscellaneous Information

- Official Documentation can be found [here](https://cryptimeleon.github.io/).
    - The *For Contributors* area includes information on how to contribute.
- Groupsig adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
- The changelog can be found [here](CHANGELOG.md).
- Groupsig is licensed under Apache License 2.0, see [LICENSE file](LICENSE).

## Authors
The library was implemented at Paderborn University in the research group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/).

## References
[DiaArrRod15] Jesus Diaz and David Arroyo and Francisco B. Rodriguez (2015). 
"libgroupsig: An extensible C library for group signatures". https://eprint.iacr.org/2015/1146

[ChoParYun06] Seung Geol Choi, Kunsoo Park, and Moti Yung (2006). "Short Traceable Signatures Based on Bilinear Pairings". 
In Advances in Information and Computer Security (pp. 88–103). Springer Berlin Heidelberg.

