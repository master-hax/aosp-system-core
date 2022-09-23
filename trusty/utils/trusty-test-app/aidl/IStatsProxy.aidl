import IStats;

//interface IStatsProxy {
//    const @utf8InCpp String PORT = "com.android.trusty.binder.istatsproxy.service";
//    void initialize(in IStats iStats);
//}

interface IStatsProxy {
    const @utf8InCpp String PORT = "com.android.trusty.binder.istatsproxy.service";
    /**
     * Report a custom vendor atom.
     *
     * @param istats A VendorAtom struct that specifies the atom ID, field
     *        types, and data from the client that must be logged in statsd.
     *        Whether or not the atom is uploaded must be determined by the
     *        atom ID and server-side configs.
     */
    void initialize(in IStats istats);

    void do_report();
    //oneway void do_report();
}
