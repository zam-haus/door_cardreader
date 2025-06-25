#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <nfc/nfc.h>
#include <freefare.h>

/*
 *0x000003:
 *   Trying to authenticate 8 keys... 0(00) AES succeeded on Key 0
 *   Max Keys: 8
 *   Application Key settings (0x19):
 *    ChangeKey Access Rights (0x01):
 *        Authentication with key 1 necessary to change any key
 *    * configuration changeable
 *    * Allow changing the Master Key
 *    Application Key versions: 0:00 1:00 2:00 3:00 4:00 5:00 6:00 7:00
 *   Found 1 file:
 *0x00:
 *  Communication settings: encrypted
 *  Access rights:
 *    Read Key:   4
 *    Write Key:  2
 *    RW Key:     3
 *    Change Key: 0
 *  File type: standard data file
 *  Size: 32 bytes
 *  Content: Can't read content with current key, reauthenticating: 4(00) AES succeeded on Key 4
 *
 *  0x0000: 34 35 34 35 34 35 34 35 34 35 34 35 30 31 00 00   45454545454501..
 *  0x0010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
 */


#define SIPORT_AID 3

#define CIP_PMK	{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }

static uint8_t pmks[][16] = {
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 },
	CIP_PMK,
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, /* FAUcard key */
};

static uint8_t cip_pmk[16] = CIP_PMK;

static uint8_t null_key_3daes[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static uint8_t cip_siport_key3[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

static uint8_t siport_keys[8][16] = {
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 },
	{ 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 },
	{ 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 },
	{ 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 },
	{ 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50 },
	{ 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60 },
	{ 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70, 0x70 },
};

/* APP 4 is SIPORT offline */
static uint8_t app4_keys[8][16] = {
	{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
	{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
	{ 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21 },
	{ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
	{ 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 },
	{ 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51 },
	{ 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61 },
	{ 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71 },
};

/* APP 5 is SIPORT biometric */
static uint8_t app5_keys[8][16] = {
	{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
	{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
	{ 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21 },
	{ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
	{ 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 },
	{ 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51 },
	{ 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61 },
	{ 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71 },
};

/* APP 17 is FAU getuid-key for trusted third parties (rommel, rrze, i4 kaffe, ...) */
static uint8_t app17_keys[8][16] = {
	{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
	{ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
	{ 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21 },
	{ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
	{ 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 },
	{ 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51, 0x51 },
	{ 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61 },
	{ 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71 },
};

static int authenticated_key;

static void read_real_keys(void);

static int try_auth_one(MifareTag tag, uint8_t keys[][16], int nKeys, uint8_t keyNo, int quiet)
{
	MifareDESFireKey key;
	uint8_t version;
	int i;
	int res = 0;

	res = mifare_desfire_get_key_version (tag, keyNo, &version);

	if (res < 0)
		version = 0x00;

	if (!quiet) {
		printf("%d(%02x) ", keyNo, version);
		fflush(stdout);
	}

	for (i = 0; i < nKeys; i++) {
		key = mifare_desfire_aes_key_new(keys[i]);
		res = mifare_desfire_authenticate_aes(tag, keyNo, key);
		mifare_desfire_key_free(key);

		if (res >= 0) {
			if (!quiet)
				printf("AES succeeded on Key %d\n", keyNo);

			authenticated_key = i;
			return 1;
		} else {
			if ((mifare_desfire_last_picc_error(tag) != AUTHENTICATION_ERROR) &&
					(mifare_desfire_last_picc_error(tag) != ILLEGAL_COMMAND_CODE)) {
				if (mifare_desfire_last_picc_error(tag) == NO_SUCH_KEY) {
					printf("failed, no such keys\n");
					return 0;
				} else {
					freefare_perror(tag, "AES");
				}
			}
		}
	}

	for (i = 0; i < nKeys; i++) {
		key = mifare_desfire_3des_key_new(keys[i]);
		mifare_desfire_key_set_version(key, version);
		res = mifare_desfire_authenticate(tag, keyNo, key);
		mifare_desfire_key_free(key);

		if (res >= 0) {
			if (!quiet)
				printf("3DES succeeded on Key %d\n", keyNo);

			authenticated_key = i;
			return 1;
		} else {
			if (mifare_desfire_last_picc_error(tag) != AUTHENTICATION_ERROR) {
				freefare_perror(tag, "3DES");
			}
		}
	}

	return 0;
}

static int try_auth_des_pmk(MifareTag tag, int quiet)
{
	MifareDESFireKey key;
	uint8_t version;
	int i;
	uint8_t des_pmk[][8] = {
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	};
	int res = 0;


	res = mifare_desfire_get_key_version (tag, 0, &version);

	if (res < 0)
		version = 0x00;

	if (!quiet) {
		printf("%d(%02x) ", 0, version);
		fflush(stdout);
	}

	for (i = 0; i < (sizeof(des_pmk)/sizeof(des_pmk[0])); i++) {
		key = mifare_desfire_des_key_new(des_pmk[i]);
		mifare_desfire_key_set_version(key, version);
		res = mifare_desfire_authenticate(tag, 0, key);
		mifare_desfire_key_free(key);

		if (res >= 0) {
			if (!quiet)
				printf("DES succeeded on Key %d\n", 0);
			authenticated_key = i;
			return 1;
		} else {
			if (mifare_desfire_last_picc_error(tag) != AUTHENTICATION_ERROR) {
				freefare_perror(tag, "DES");
			}
		}
	}

	return 0;
}

int auth_aid(MifareTag tag, uint8_t keys[][16], int nKeys, int appId, uint8_t keyNo)
{
	MifareDESFireAID aid;
	int res;

	aid = mifare_desfire_aid_new(appId);

	res = mifare_desfire_select_application(tag, aid);
	free(aid);
	if (res < 0) {
		freefare_perror(tag, "Select AID failed");
		printf("\n");
		return 0;
	}

	if (!try_auth_one(tag, keys, nKeys, keyNo, 0)) {
		fprintf(stderr, "Can't authenticate key!\n");
		return 0;
	}

	return 1;
}

int init_tag(MifareTag tag)
{
	MifareDESFireKey key;
	int res;

	read_real_keys();

	authenticated_key = -1;
	if (!try_auth_des_pmk(tag, 0)) {
		if (!auth_aid(tag, pmks, sizeof(pmks)/sizeof(pmks[0]), 0, 0)) {
			return 0;
		}
	}

	if (authenticated_key == (sizeof(pmks)/sizeof(pmks[0])-1)) {
		fprintf(stderr, "Won't format a FAUcard!\n");
		return 0;
	}

	printf("Setting CIP Master Key...\n");
	key = mifare_desfire_aes_key_new_with_version(cip_pmk, 0x42);
	res = mifare_desfire_change_key(tag, 0x80, key, NULL);
	mifare_desfire_key_free(key);
	if (res < 0) {
		freefare_perror(tag, "Can't change key");
		printf("\n");
		return 0;
	}

	printf("Reauthenticating...\n");
	if (!auth_aid(tag, pmks, sizeof(pmks)/sizeof(pmks[0]), 0, 0)) {
		return 0;
	}

	printf("Changing master key settings...\n");
	res = mifare_desfire_change_key_settings (tag, 0xF);
	if (res < 0) {
		freefare_perror(tag, "Can't change key settings");
		printf("\n");
		return 0;
	}

	printf("Formatting PICC...\n");
	res = mifare_desfire_format_picc(tag);
	if (res < 0) {
		freefare_perror(tag, "Can't format PICC");
		printf("\n");
		return 0;
	}

	return 1;
}

int create_app(MifareTag tag, int iAID, uint8_t keys[][16], int nKeys, uint8_t app_settings)
{
	MifareDESFireKey key;
	MifareDESFireAID aid;
	MifareDESFireAID master_aid;
	uint8_t settings;
	uint8_t max_keys;
	int k;
	int res;

	master_aid = mifare_desfire_aid_new(0x00);
	aid = mifare_desfire_aid_new(iAID);

	res = mifare_desfire_select_application(tag, master_aid);
	free(master_aid);
	if (res < 0) {
		freefare_perror(tag, "Select Master AID failed");
		printf("\n");
		return 0;
	}

	res = mifare_desfire_get_key_settings(tag, &settings, &max_keys);
	if (res != 0) {
		settings = 0x00;
	}

	/* 0x04: PICC Master Key not required for create / delete */
	if (!(settings & 0x04)) {
		printf("Authenticating...\n");
		if (!auth_aid(tag, pmks, sizeof(pmks)/sizeof(pmks[0]), 0, 0)) {
			return 0;
		}
	}

	printf("Creating Application...\n");

	/* 8 Keys, Application Key Settings 0x19 */
	res = mifare_desfire_create_application_aes(tag, aid, app_settings, nKeys);
	if (res < 0) {
		freefare_perror(tag, "Can't create application");
		printf("\n");
		return 0;
	}

	printf("Authenticating to application with null master key...\n");
	if (!auth_aid(tag, &null_key_3daes, 1, iAID, 0)) {
		return 0;
	}

	for (k = 0; k < 8; k++) {
		printf("Setting application key %d...\n", k);
		key = mifare_desfire_aes_key_new_with_version(keys[k], 0x00);
		res = mifare_desfire_change_key(tag, k, key, NULL);
		mifare_desfire_key_free(key);
		if (res < 0) {
			freefare_perror(tag, "Can't change key");
			printf("\n");
			return 0;
		}
		if (k == 0 || k == 1) {
			if (!auth_aid(tag, &(keys[k]), 1, iAID, k)) {
				return 0;
			}
		}
	}
	free(aid);

	return 1;
}

int create_siport_app(MifareTag tag)
{
	uint8_t app_keys[8][16];
	int res;

	read_real_keys();

	memcpy(app_keys, siport_keys, sizeof(app_keys));
	memcpy(app_keys[3], cip_siport_key3, sizeof(cip_siport_key3));

	if (!create_app(tag, SIPORT_AID, app_keys, 0x8, 0x19)) {
		return 0;
	}

	printf("Authenticating to SIPORT application with master key...\n");
	if (!auth_aid(tag, &(siport_keys[0]), 1, SIPORT_AID, 0)) {
		return 0;
	}

	printf("Creating standard data file...\n");
	/*
	 * 0x00:
	 *  Communication settings: encrypted
	 *  Access rights:
	 *    Read Key:   4
	 *    Write Key:  2
	 *    RW Key:     3
	 *    Change Key: 0
	 */
	res = mifare_desfire_create_std_data_file(tag, 0x00, MDCM_ENCIPHERED,
			MDAR(MDAR_KEY4, MDAR_KEY2, MDAR_KEY3, MDAR_KEY0), 32);
	if (res < 0) {
		freefare_perror(tag, "Can't create file");
		printf("\n");
		return 0;
	}

	return 1;
}

int create_siport_app4(MifareTag tag)
{
	int res;

	read_real_keys();

	if (!create_app(tag, 0x4, app4_keys, sizeof(app4_keys)/sizeof(app4_keys[0]), 0x19)) {
		return 0;
	}

	printf("Authenticating to SIPORT offline application with master key...\n");
	if (!auth_aid(tag, &(app4_keys[0]), 1, 0x4, 0)) {
		return 0;
	}

	printf("Creating standard data file...\n");
	/*
	 * 0x00:
	 *  Communication settings: encrypted
	 *  Access rights:
	 *    Read Key:   4
	 *    Write Key:  2
	 *    RW Key:     3
	 *    Change Key: 0
	 */
	res = mifare_desfire_create_std_data_file(tag, 0x00, MDCM_ENCIPHERED,
			MDAR(MDAR_KEY4, MDAR_KEY2, MDAR_KEY3, MDAR_KEY0), 800);
	if (res < 0) {
		freefare_perror(tag, "Can't create file");
		printf("\n");
		return 0;
	}

	return 1;
}

int create_siport_app5(MifareTag tag)
{
	int res;

	read_real_keys();

	if (!create_app(tag, 0x5, app5_keys, sizeof(app5_keys)/sizeof(app5_keys[0]), 0x19)) {
		return 0;
	}

	printf("Authenticating to SIPORT biometric application with master key...\n");
	if (!auth_aid(tag, &(app5_keys[0]), 1, 0x5, 0)) {
		return 0;
	}

	printf("Creating standard data file...\n");
	/*
	 * 0x00:
	 *  Communication settings: encrypted
	 *  Access rights:
	 *    Read Key:   4
	 *    Write Key:  2
	 *    RW Key:     3
	 *    Change Key: 0
	 */
	res = mifare_desfire_create_std_data_file(tag, 0x00, MDCM_ENCIPHERED,
			MDAR(MDAR_KEY4, MDAR_KEY2, MDAR_KEY3, MDAR_KEY0), 1000);
	if (res < 0) {
		freefare_perror(tag, "Can't create file");
		printf("\n");
		return 0;
	}

	return 1;
}

static void read_real_keys(void) {
	static int have_real_keys = 0;
	int pipefds[2];
	pid_t gpg_pid;

	if (have_real_keys)
		return;

	if (pipe(pipefds) != 0) {
		perror("pipe!\n");
		exit(EXIT_FAILURE);
	}

	gpg_pid = fork();
	if (gpg_pid == 0) {
		close(pipefds[0]);
		if (dup2(pipefds[1], STDOUT_FILENO) != STDOUT_FILENO) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}
		close(pipefds[1]);
		execlp("gpg", "gpg", "-d", "siportkeys.gpg", NULL);
		exit(EXIT_FAILURE);
	} else if (gpg_pid != -1) {
		int wait_status;
		char c;
		ssize_t ret;
		int index;

		close(pipefds[1]);

		index = sizeof(pmks)/sizeof(pmks[0])-1;
		ret = read(pipefds[0], pmks[index], sizeof(pmks[index]));
		if (ret != sizeof(pmks[index])) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		printf("PICC master key with length %zd read!\n", ret);

		ret = read(pipefds[0], siport_keys, sizeof(siport_keys));
		if (ret != sizeof(siport_keys)) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		printf("siport keys with length %zd read!\n", ret);

		ret = read(pipefds[0], app4_keys, sizeof(app4_keys));
		if (ret != sizeof(app4_keys)) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		printf("app4 keys with length %zd read!\n", ret);

		ret = read(pipefds[0], app5_keys, sizeof(app5_keys));
		if (ret != sizeof(app5_keys)) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		printf("app5 keys with length %zd read!\n", ret);

		ret = read(pipefds[0], app17_keys, sizeof(app17_keys));
		if (ret != sizeof(app17_keys)) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		printf("app17 keys with length %zd read!\n", ret);

		while(1) {
			ssize_t ret;

			ret = read(pipefds[0], &c, 1);
			if (ret > 0) {
			} else if (ret == 0) {
				break;
			} else {
				perror("read");
				exit(EXIT_FAILURE);
			}
		}

		close(pipefds[0]);

		if (waitpid(gpg_pid, &wait_status, 0) != gpg_pid) {
			perror("waitpid");
			exit(EXIT_FAILURE);
		}

		if ((!WIFEXITED(wait_status)) || (WEXITSTATUS(wait_status) != 0)) {
			fprintf(stderr, "gpg returned with exit status: %d\n", WEXITSTATUS(wait_status));
			exit(EXIT_FAILURE);
		}
	} else {
		perror("fork failed...\n");
		exit(EXIT_FAILURE);
	}

	have_real_keys = 1;

	return;
}

int main(int argc, char *argv[])
{
	MifareTag *tags = NULL;
	nfc_connstring devices[8];
	nfc_device **device;
	char *id;
	size_t device_count;
	int res;
	int format = 0;
	int read_only = 0;

	id = argv[1];

	if ((argc == 3) && (!(strcmp(argv[1], "-f")))) {
		id = argv[2];
		format = 1;
		argc--;
	}

	if ((argc == 2) && (!(strcmp(argv[1], "-r")))) {
		read_only = 1;
	}

	if (argc != 2) {
		fprintf(stderr, "Syntax: %s [-f|-r] new_id\n\n", argv[0]);
		fprintf(stderr, "\t-f\tFormat card (beware!)\n");
		fprintf(stderr, "\t-r\tOnly read and display current SIPORT id\n");
		exit(EXIT_FAILURE);
	}

	device_count = nfc_list_devices(NULL, devices, 8);
	if (!device_count) {
		fprintf(stderr, "No NFC device found\n");
		exit(EXIT_FAILURE);
	}

	device = malloc(sizeof(nfc_device*) * device_count);
	if (!device) {
		fprintf(stderr, "Can't allocate memory\n");
		exit(EXIT_FAILURE);
	}

	for (size_t d = 0; d < device_count; d++) {
		device[d] = nfc_open(NULL, devices[d]);
		if (!device[d]) {
			fprintf(stderr, "nfc_connect to device %zd failed\n", d);
			continue;
		}
	}

	while(1) {
		for (size_t d = 0; d < device_count; d++) {
			tags = freefare_get_tags(device[d]);
			if (!tags) {
				continue;
			}

			for (int i = 0; tags[i]; i++) {
				MifareDESFireAID aid;
				uint8_t siport_content[128];
				int k;

				if (DESFIRE != freefare_get_tag_type(tags[i]))
					continue;

				printf("Found DESFIRE tag: %s\n", freefare_get_tag_uid(tags[i]));

				res = mifare_desfire_connect(tags[i]);
				if (res < 0) {
					fprintf(stderr,"Can't connect to Mifare DESFire target.");
					continue;
				}

				printf("Trying to select SIPORT application...\n");
				aid = mifare_desfire_aid_new(SIPORT_AID);
				res = mifare_desfire_select_application(tags[i], aid);
				free(aid);

				if (res < 0) {
					printf("Application not on tag!\n");

					if (read_only)
						exit(EXIT_FAILURE);
				}

				if (!read_only && (res < 0 || format)) {
					aid = mifare_desfire_aid_new(0);
					res = mifare_desfire_select_application(tags[i], aid);
					free(aid);

					read_real_keys();

					if (format) {
						printf("Trying to format tag... ");
						if(!init_tag(tags[i])) {
							exit(EXIT_FAILURE);
						}
					}

					aid = mifare_desfire_aid_new(SIPORT_AID);
					res = mifare_desfire_select_application(tags[i], aid);
					free(aid);

					if (res < 0) {
						printf("Creating SIPORT application\n");
						create_siport_app(tags[i]);
					}

					aid = mifare_desfire_aid_new(0x4);
					res = mifare_desfire_select_application(tags[i], aid);
					free(aid);

					if (res < 0) {
						printf("Creating SIPORT offline application\n");
						create_siport_app4(tags[i]);
					}

					aid = mifare_desfire_aid_new(0x5);
					res = mifare_desfire_select_application(tags[i], aid);
					free(aid);

					if (res < 0) {
						printf("Creating SIPORT biometric application\n");
						create_siport_app5(tags[i]);
					}

					aid = mifare_desfire_aid_new(0x17);
					res = mifare_desfire_select_application(tags[i], aid);
					free(aid);

					if (res < 0) {
						printf("Creating application 0x17\n");
						create_app(tags[i], 0x17, app17_keys, sizeof(app17_keys)/sizeof(app17_keys[0]), 0x19);
					}
				}

				k = 3;
				printf("Authenticating with CIP RW key... ");
				if (!auth_aid(tags[i], &(cip_siport_key3), 1, SIPORT_AID, k)) {
					printf("Authenticating with SIPORT RW key... ");
					read_real_keys();
					if (!auth_aid(tags[i], &(siport_keys[k]), 1, SIPORT_AID, k)) {
						exit(EXIT_FAILURE);
					}
				}

				bzero(siport_content, sizeof(siport_content));
				res = mifare_desfire_read_data_ex(tags[i], 0x00, 0, 32, siport_content, MDCM_ENCIPHERED);
				if (res > 0) {
					if (!read_only)
						printf("Old ");

					printf("SIPORT ID: %s\n", siport_content);
				}

				if (read_only)
					exit(EXIT_SUCCESS);

				bzero(siport_content, sizeof(siport_content));
				snprintf((char*)siport_content, sizeof(siport_content), "00000000000000");
				memcpy((char*)siport_content + (14 - strlen(id)), id, strlen(id));

				printf("New SIPORT ID: %s\n", siport_content);
				res = mifare_desfire_write_data_ex(tags[i], 0x00, 0, 32, siport_content, MDCM_ENCIPHERED);
				if (res < 0) {
					freefare_perror(tags[i], "Can't write to file");
					printf("\n");
					exit(EXIT_FAILURE);
				}
				printf("%d bytes written!\n", res);

				exit(EXIT_SUCCESS);
			}
			freefare_free_tags(tags);
		}
	}

	for (size_t d = 0; d < device_count; d++) {
		nfc_close(device[d]);
	}

	exit(EXIT_SUCCESS);
}
