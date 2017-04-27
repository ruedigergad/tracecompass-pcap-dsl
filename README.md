
Begin of Note

Note: This is not the official Trace Compass repository.
The code in this repository was forked from Trace Compass.
If you are looking for the official Trace Compass repository etc. go to the following websites:



The aim of the code in this repository is to serve as an experiment and proof-of-concept prototype for importing packet capture traces into Trace Compass via a Clojure based Domain Specific Language (DSL).
The aim of the DSL-based packet capture import is to ease the import of packet capture traces by providing a more flexible, dynamic, and extendible for importing packet capture traces.

The author of the changes done in this repository is Ruediger Gad (r.c.g@gmx.de).
All changes done in this repository are released under the terms of the Eclipse Public License (EPL) 1.0.
This is the same license as for the original Trace Compass code on which this work is based on.

End of Note


Eclipse Trace Compass
=====================

This source tree contains the source code for the Trace Compass plugins for
Eclipse.

The plugins are categorized as follows:

    analysis/    | Generic extensions to the base framework
    btf/         | Best Trace Format (BTF) integration
    common/      | Generic utilities that can be used by other plugins
    ctf/         | Common Trace Format (CTF) reader library
    doc/         | Documentation and code examples
    gdbtrace/    | Support for reading and viewing GDB traces
    lttng/       | LTTng integration
    pcap/        | libpcap integration
    rcp/         | Code specific to the RCP version
    releng/      | Releng-related plugins
    statesystem/ | State System library
    tmf/         | Core framework

See the `components.svg` file for a diagram showing the dependencies between the
different components.


Setting up the development environment
--------------------------------------

To set up the environment to build Trace Compass from within Eclipse, see this
wiki page:
<http://wiki.eclipse.org/Trace_Compass/Development_Environment_Setup>


Compiling manually
------------------

The Maven project build requires version 3.3 or later. It can be downloaded from
<http://maven.apache.org> or from the package management system of your distro.

To build the project manually using Maven, simply run the following command from
the top-level directory:

    mvn clean install

The default command will compile and run the unit tests. Running the tests can
take some time, to skip them you can append `-Dmaven.test.skip=true` to the
`mvn` command:

    mvn clean install -Dmaven.test.skip=true

Stand-alone application (RCP) packages will be placed in
`rcp/org.eclipse.tracecompass.rcp.product/target/products`.

The p2 update site, used for installation as plugins inside Eclipse, will be
placed in `releng/org.eclipse.tracecompass.releng-site/target/repository`.


Maven profiles and properties
-----------------------------

The following Maven profiles and properties are defined in
the build system. You can set them by using `-P[profile name]` and
`-D[property name]=[value]` in `mvn` commands.

* `-Dtarget-platform=[target]`

  Defines which target to use. This is used to build against various versions of
  the Eclipse platform. Available ones are in
  `releng/org.eclipse.tracecompass.target`. The default is usually the latest
  stable platform. To use the staging target for example, use
  `-Dtarget-platform=tracecompass-eStaging`.

* `-Dskip-automated-ui-tests`

  Skips the automated UI integration tests. Not required when using
  `-Dmaven.test.skip=true`, which already skips all the tests.

* `-Dskip-rcp`

  Skips building the RCP archives and related deployment targets. Only works in
  conjunction with `-Dskip-automated-ui-tests`, due to a limitation in Maven.

* `-Pctf-grammar`

  Re-compiles the CTF grammar files. This should be enabled if you modify the
  `.g` files in the `ctf.parser` plugin.

* `-Prun-custom-test-suite`

  Runs a test suite present in `releng/org.eclipse.tracecompass.alltests`. The
  test suite to run has to be defined by `-DcustomTestSuite=[name]`, for example
  `-DcustomTestSuite=RunAllPerfTests`.

* `-Pdeploy-rcp`

  Mainly for use on build servers. Copies the generated RCP archives, as well as
  the RCP-specific update site, to the paths specified by
  `-DrcpDestination=/absolute/path/to/destination` and
  `-DrcpSiteDestination=/absolute/path/to/destination`, respectively.

* `-Pdeploy-update-site`

  Mainly for use on build servers. Copies the standard update site (for the
  Eclipse plugin installation) to the destination specified by
  `-DsiteDestination=/absolute/path/to/destination`.

* `-Psign-update-site`

  Mainly for use on build servers. Signs all the generated update sites using
  the Eclipse signing server.

* `-Pdeploy-doc`

  Mainly for use on build servers. Copies the generated HTML documentation to
  the destination specified by `-DdocDestination=/absolute/path/to/destination`.
  Some directories may need to already exist at the destination (or Maven will
  throw related errors).

