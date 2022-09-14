hd7f0b:
cd EFI\BOOT\
mkdir TEST_OUTPUT
tools\AtlGetNcb.efi > TEST_OUTPUT\switchNCB.txt
tools\AtlSwitchNcb.efi >> TEST_OUTPUT\switchNCB.txt
tools\AtlGetNcb.efi >> TEST_OUTPUT\switchNCB.txt
tools\AtlSwitchNcb.efi >> TEST_OUTPUT\switchNCB.txt
tools\AtlGetNcb.efi >> TEST_OUTPUT\switchNCB.txt

tools\AtlSwitchNcb.efi -dev_num 0 > TEST_OUTPUT\switchNCB_dev_num_0.txt
tools\AtlSwitchNcb.efi
tools\AtlSwitchNcb.efi -dev_num 20 > TEST_OUTPUT\switchNCB_dev_num_20.txt
tools\AtlSwitchNcb.efi -dev_num 21 > TEST_OUTPUT\switchNCB_dev_num_21.txt
tools\AtlSwitchNcb.efi -h > TEST_OUTPUT\switchNCB_help.txt
tools\AtlSwitchNcb.efi -v > TEST_OUTPUT\switchNCB_version.txt

tools\AtlGetNcb.efi -dev_num 0 > TEST_OUTPUT\getNCB_dev_num_0.txt
tools\AtlGetNcb.efi -dev_num 20 > TEST_OUTPUT\getNCB_dev_num_20.txt
tools\AtlGetNcb.efi -dev_num 21 > TEST_OUTPUT\getNCB_dev_num_21.txt
tools\AtlGetNcb.efi -h > TEST_OUTPUT\getNCB_help.txt
tools\AtlGetNcb.efi -v > TEST_OUTPUT\getNCB_version.txt

tools\AtlEfuseRead.efi > TEST_OUTPUT\EfuseRead.txt
tools\AtlEfuseRead.efi -dev_num 0 > TEST_OUTPUT\EfuseRead_dev_num_0.txt
tools\AtlEfuseRead.efi -dev_num 20 > TEST_OUTPUT\EfuseRead_dev_num_20.txt
tools\AtlEfuseRead.efi -dev_num 21 > TEST_OUTPUT\EfuseRead_dev_num_21.txt
tools\AtlEfuseRead.efi -h > TEST_OUTPUT\EfuseRead_help.txt
tools\AtlEfuseRead.efi -v > TEST_OUTPUT\EfuseRead_version.txt

tools\AtlDumpFlash.efi > TEST_OUTPUT\DumpFlash.txt
tools\AtlDumpFlash.efi -dev_num 0 > TEST_OUTPUT\DumpFlash_dev_num_0.txt
tools\AtlDumpFlash.efi -dev_num 20 > TEST_OUTPUT\DumpFlash_dev_num_20.txt
tools\AtlDumpFlash.efi -dev_num 21 > TEST_OUTPUT\DumpFlash_dev_num_21.txt
tools\AtlDumpFlash.efi -h > TEST_OUTPUT\DumpFlash_help.txt
tools\AtlDumpFlash.efi -v > TEST_OUTPUT\DumpFlash_version.txt

tools\AtlEfuseBurnB1.efi -ncbstart 1 -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbstart_1.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbstart_0.txt
tools\AtlEfuseBurnB1.efi -ncbstart 10 -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbstart_10.txt
tools\AtlEfuseBurnB1.efi -ncbstart -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbstart.txt
tools\AtlEfuseBurnB1.efi -ncbstart 1 -ncbend 0 -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbend_0.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -ncbend 1 -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbend_1.txt
tools\AtlEfuseBurnB1.efi -ncbend 10 -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbend_10.txt
tools\AtlEfuseBurnB1.efi -ncbend -dry_run > TEST_OUTPUT\EfuseBurnB1_ncbend.txt

tools\AtlSwitchNcb.efi
tools\AtlEfuseBurnB1.efi -ncbstart 0 -flashless 0 -dry_run > TEST_OUTPUT\EfuseBurnB1_flashless_0.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -flashless 1 -dry_run > TEST_OUTPUT\EfuseBurnB1_flashless_1.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -flashless -dry_run > TEST_OUTPUT\EfuseBurnB1_flashless.txt

tools\AtlEfuseBurnB1.efi -ncbstart 0 -dis_pcicfg_flash 0 -dry_run > TEST_OUTPUT\EfuseBurnB1_pcicfg_0.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -dis_pcicfg_flash 1 -dry_run > TEST_OUTPUT\EfuseBurnB1_pcicfg_1.txt

tools\AtlEfuseBurnB1.efi -ncbstart 0 -lock_bit 0 -dry_run > TEST_OUTPUT\EfuseBurnB1_lock_bit_0.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -lock_bit 1 -dry_run > TEST_OUTPUT\EfuseBurnB1_lock_bit_1.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -lock_bit 1 -sha_bin tools\sha256.bin -dry_run > TEST_OUTPUT\EfuseBurnB1_lock_bit_sha.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -lock_bit 10 -dry_run > TEST_OUTPUT\EfuseBurnB1_lock_bit_10.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -lock_bit -dry_run > TEST_OUTPUT\EfuseBurnB1_lock_bit.txt

tools\AtlEfuseBurnB1.efi -ncbstart 0 -mac_addr 11-22-33-44-55-66 -dry_run > TEST_OUTPUT\EfuseBurnB1_mac.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -mac_addr 121-22-33-44-55-66 -dry_run > TEST_OUTPUT\EfuseBurnB1_mac_incorrect.txt

tools\AtlEfuseBurnB1.efi -ncbstart 0 -pcicfg_bin tools\pcicfg.bin -dry_run > TEST_OUTPUT\EfuseBurnB1_pcicfg_bin.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -pcicfg_bin tools\sha256.bin -dry_run > TEST_OUTPUT\EfuseBurnB1_pcicfg_bin_incorrect.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -sha_bin tools\sha256.bin -dry_run > TEST_OUTPUT\EfuseBurnB1_sha_bin.txt
tools\AtlEfuseBurnB1.efi -ncbstart 0 -sha_bin tools\pcicfg.bin -dry_run > TEST_OUTPUT\EfuseBurnB1_sha_bin_incorrect.txt

tools\AtlEfuseBurnB1.efi -ncbstart 0 -dev_num 0 > TEST_OUTPUT\EfuseBurnB1_dev_num_0.txt
tools\AtlEfuseBurnB1.efi -dev_num 20 > TEST_OUTPUT\EfuseBurnB1_dev_num_20.txt
tools\AtlEfuseBurnB1.efi -dev_num 21 > TEST_OUTPUT\EfuseBurnB1_dev_num_21.txt
tools\AtlEfuseBurnB1.efi -h > TEST_OUTPUT\EfuseBurnB1_help.txt
tools\AtlEfuseBurnB1.efi -v > TEST_OUTPUT\EfuseBurnB1_version.txt

tools\AtlReadReg.efi 18 > TEST_OUTPUT\ReadReg_18.txt
tools\AtlReadReg.efi -dev_num 0 > TEST_OUTPUT\ReadReg_dev_num_0.txt
tools\AtlReadReg.efi 18 -dev_num 20 > TEST_OUTPUT\ReadReg_dev_num_20.txt
tools\AtlReadReg.efi -dev_num 21 > TEST_OUTPUT\ReadReg_dev_num_21.txt
tools\AtlReadReg.efi -h > TEST_OUTPUT\ReadReg_help.txt
tools\AtlReadReg.efi -v > TEST_OUTPUT\ReadReg_version.txt

tools\AtlResetDone.efi > TEST_OUTPUT\ResetDone.txt
tools\AtlResetDone.efi -dev_num 0 > TEST_OUTPUT\ResetDone_dev_num_0.txt
tools\AtlResetDone.efi -dev_num 20 > TEST_OUTPUT\ResetDone_dev_num_20.txt
tools\AtlResetDone.efi -dev_num 21 > TEST_OUTPUT\ResetDone_dev_num_21.txt
tools\AtlResetDone.efi -h > TEST_OUTPUT\ResetDone_help.txt
tools\AtlResetDone.efi -v > TEST_OUTPUT\ResetDone_version.txt

tools\AtlChipReset.efi > TEST_OUTPUT\ChipReset.txt
tools\AtlChipReset.efi -phy_id 0 > TEST_OUTPUT\ChipReset_phy_0.txt
tools\AtlChipReset.efi -phy_id 1 > TEST_OUTPUT\ChipReset_phy_1.txt
tools\AtlChipReset.efi -phy_id 1 -skip_phy_kickstart > TEST_OUTPUT\ChipReset_skip.txt
tools\AtlChipReset.efi -dev_num 0 > TEST_OUTPUT\ChipReset_dev_num_0.txt
tools\AtlChipReset.efi -dev_num 20 > TEST_OUTPUT\ChipReset_dev_num_20.txt
tools\AtlChipReset.efi -dev_num 21 > TEST_OUTPUT\ChipReset_dev_num_21.txt
tools\AtlChipReset.efi -h > TEST_OUTPUT\ChipReset_help.txt
tools\AtlChipReset.efi -v > TEST_OUTPUT\ChipReset_version.txt
