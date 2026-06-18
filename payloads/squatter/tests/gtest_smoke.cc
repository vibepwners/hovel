#include <gtest/gtest.h>

TEST(Smoke, Arithmetic) { EXPECT_EQ(2 + 2, 4); }
TEST(Smoke, Strings) { EXPECT_STREQ("ab", "ab"); }
TEST(Smoke, Vector) {
    int xs[3] = {1, 2, 3};
    int sum = 0;
    for (int i = 0; i < 3; ++i) sum += xs[i];
    EXPECT_EQ(sum, 6);
}
