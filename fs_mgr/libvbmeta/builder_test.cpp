#include <gtest/gtest.h>
#include <libvbmeta/builder.h>
#include <libvbmeta/footer_format.h>

using namespace android::fs_mgr;

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

TEST(BuilderTest, SuperAVBFooterBuilderBasic) {
  std::unique_ptr<SuperAVBFooterBuilder> builder =
      std::make_unique<SuperAVBFooterBuilder>();
  ASSERT_NE(builder, nullptr);

  EXPECT_TRUE(builder->Init("system", 3E10, 5E3));
  EXPECT_TRUE(builder->Init("product", 4E10, 6E3));

  std::unique_ptr<SuperAVBFooter> footer = builder->Export();
  ASSERT_NE(footer, nullptr);

  // check for header
  EXPECT_EQ(footer->header.magic, SUPER_AVB_FOOTER_MAGIC);
  EXPECT_EQ(footer->header.major_version, SUPER_AVB_FOOTER_MAJOR_VERSION);
  EXPECT_EQ(footer->header.minor_version, SUPER_AVB_FOOTER_MINOR_VERSION);
  EXPECT_EQ(footer->header.header_size, SUPER_AVB_FOOTER_HEADER_SIZE);
  EXPECT_EQ(footer->header.total_size,
            SUPER_AVB_FOOTER_HEADER_SIZE +
                SUPER_AVB_FOOTER_DESCRIPTOR_SIZE * 2 + 13);
  EXPECT_EQ(footer->header.descriptors_size,
            SUPER_AVB_FOOTER_DESCRIPTOR_SIZE * 2 + 13);

  // Test for descriptors
  EXPECT_EQ(footer->descriptors.size(), 2);

  EXPECT_EQ(footer->descriptors[0].vbmeta_offset, 4E10);
  EXPECT_EQ(footer->descriptors[0].vbmeta_size, 6E3);
  EXPECT_EQ(footer->descriptors[0].partition_name_length, 7);
  for (int i = 0; i < 48; i++)
    EXPECT_EQ(footer->descriptors[0].reserved[i], 0);
  EXPECT_STREQ(footer->descriptors[0].partition_name, "product");

  EXPECT_EQ(footer->descriptors[1].vbmeta_offset, 3E10);
  EXPECT_EQ(footer->descriptors[1].vbmeta_size, 5E3);
  EXPECT_EQ(footer->descriptors[1].partition_name_length, 6);
  for (int i = 0; i < 48; i++)
    EXPECT_EQ(footer->descriptors[1].reserved[i], 0);
  EXPECT_STREQ(footer->descriptors[1].partition_name, "system");
}

TEST(BuilderTest, SuperFooterBuilderBasic) {
  std::unique_ptr<SuperFooterBuilder> builder =
      std::make_unique<SuperFooterBuilder>(7E10);
  ASSERT_NE(builder, nullptr);

  std::unique_ptr<SuperFooter> footer = builder->Export();
  ASSERT_NE(footer, nullptr);

  EXPECT_EQ(footer->magic, SUPER_FOOTER_MAGIC);
  EXPECT_EQ(footer->major_version, SUPER_FOOTER_MAJOR_VERSION);
  EXPECT_EQ(footer->minor_version, SUPER_FOOTER_MINOR_VERSION);
  EXPECT_EQ(footer->avbfooter_offset, 7E10);
  for (int i = 0; i < 48; i++)
    EXPECT_EQ(footer->reserved[i], 0);
}