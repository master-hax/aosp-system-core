typedef uint32_t arm_ptr_t;
typedef uint32_t arm_reg_t;

enum ArmRegs : size_t {
  ARM_SP = 13,
  ARM_LR = 14,
  ARM_PC = 15,
};

struct StateArm {
  arm_reg_t regs[16];
  arm_ptr_t cfa;
};
