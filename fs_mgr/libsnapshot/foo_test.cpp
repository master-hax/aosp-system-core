
#include <gtest/gtest.h>

TEST(Foo) {
}

class FooEnv : public ::testing::Environment {
  public:
    ~FooEnv() override {}
    void SetUp() override {
        GTEST_SKIP() << "SKIPPED";
    }
};

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new FooEnv());
    return RUN_ALL_TESTS();
}
