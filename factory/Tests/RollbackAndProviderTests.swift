enum RollbackAndProviderTests {
    static let all: [TestCase] =
        RollbackCoreTests.all
        + CloudflareTests.all
        + TailscaleTests.all
        + OpenRouterTests.all
        + PlanetScaleTests.all
        + GitLabAndFlyTests.all
}
