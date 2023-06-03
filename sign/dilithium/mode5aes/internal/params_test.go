package internal

import (
	"testing"

	"go.bryk.io/circl/sign/dilithium/internal/common"
)

// Tests specific to the current mode

func TestVectorDeriveUniformLeqEta(t *testing.T) {
	var p common.Poly
	var seed [64]byte
	p2 := common.Poly{
		8380416, 0, 2, 8380415, 1, 1, 0, 1, 0, 1, 8380415, 2,
		8380415, 8380415, 2, 2, 2, 1, 0, 2, 8380416, 1, 8380415,
		8380415, 8380416, 8380415, 8380416, 8380415, 1, 1, 0, 1,
		0, 1, 2, 8380416, 2, 1, 8380416, 1, 1, 2, 0, 8380416,
		8380416, 2, 0, 2, 8380415, 0, 1, 2, 1, 1, 1, 0, 8380415,
		1, 2, 8380415, 8380416, 1, 8380415, 0, 1, 8380416, 8380416,
		8380415, 0, 2, 8380415, 1, 8380416, 0, 8380416, 8380416,
		8380416, 2, 2, 1, 2, 8380415, 2, 0, 8380415, 8380415, 0,
		2, 8380415, 8380415, 1, 8380415, 2, 8380415, 0, 1, 2,
		8380415, 8380416, 8380415, 0, 8380416, 1, 0, 2, 0, 2,
		8380415, 8380416, 2, 1, 8380415, 1, 8380416, 1, 8380415,
		8380415, 0, 8380416, 0, 0, 0, 0, 0, 2, 1, 2, 0, 0, 8380415,
		8380416, 2, 0, 1, 8380416, 2, 1, 8380416, 2, 1, 8380416,
		0, 2, 8380416, 2, 0, 8380415, 0, 2, 0, 8380415, 1, 0,
		8380415, 2, 8380416, 8380416, 8380415, 0, 0, 8380416, 2,
		2, 1, 8380416, 2, 1, 2, 0, 8380415, 1, 0, 2, 2, 1, 0, 0,
		1, 2, 0, 2, 0, 2, 2, 0, 0, 2, 2, 8380416, 2, 2, 0, 8380415,
		1, 2, 2, 1, 1, 8380415, 8380415, 2, 2, 1, 8380416, 8380415,
		2, 1, 0, 8380416, 8380415, 8380415, 0, 1, 0, 8380416,
		8380416, 8380416, 8380416, 2, 8380415, 1, 8380415, 0, 1,
		0, 8380416, 2, 8380415, 2, 1, 2, 1, 1, 0, 8380415, 2,
		8380416, 8380416, 8380415, 8380415, 0, 2, 8380416, 1,
		8380416, 8380415, 8380416, 8380415, 2, 8380416, 2, 8380415,
		2, 2, 1, 8380415,
	}
	for i := 0; i < 64; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniformLeqEta(&p, &seed, 30000)
	p.Normalize()
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}

func TestVectorDeriveUniformLeGamma1(t *testing.T) {
	var p, p2 common.Poly
	var seed [64]byte
	p2 = common.Poly{
		91453, 8134283, 8211453, 8218977, 8362980, 431655, 98537,
		320966, 7892886, 144675, 495826, 7910635, 308711, 8024934,
		8314212, 8323958, 8242606, 7947101, 419492, 427692, 354075,
		21485, 456475, 213575, 362300, 8142303, 8322444, 7885879,
		89158, 181715, 8094655, 8303634, 8060028, 7920325, 192378,
		7910586, 7897074, 8097343, 7899868, 8339413, 73206, 237312,
		8183555, 348083, 8154041, 8364746, 8078364, 8312790, 105195,
		8037823, 8356712, 7994594, 240882, 70742, 8109371, 8176349,
		467152, 51422, 340432, 8030176, 342172, 154911, 64858,
		97614, 212758, 8285880, 521738, 326395, 296748, 8111442,
		8016327, 7953747, 158922, 330421, 8331843, 449771, 168214,
		8198309, 8228760, 7940533, 2498, 305217, 475829, 8037995,
		8250962, 305070, 8217080, 432779, 213808, 8162729, 381514,
		7995827, 7989202, 129047, 246099, 67554, 8233257, 398954,
		223629, 444125, 150369, 223365, 159236, 55259, 172419,
		163583, 354428, 8263789, 8017325, 8229594, 32340, 490228,
		450684, 8069619, 53733, 7932894, 7955848, 8197876, 201557,
		8307246, 446889, 8211538, 7889784, 8071108, 496027, 8159198,
		8037, 7973907, 248186, 4806, 185437, 457847, 138862, 8124477,
		284692, 8255820, 8068729, 8292005, 244272, 8061114, 21475,
		8058902, 421466, 8306487, 455649, 8218652, 7634, 148216,
		7951766, 394889, 8127579, 366374, 8062903, 8139245, 367068,
		8281027, 734, 396374, 7969282, 7977632, 8098596, 343569,
		8191282, 223874, 163783, 203572, 109732, 8229113, 8128208,
		321529, 296492, 8202474, 50404, 8336017, 8190899, 8191497,
		8279167, 336877, 7878526, 7922949, 7974614, 8076047, 8201365,
		8334333, 416495, 8090175, 150066, 7947253, 474615, 7937629,
		8027358, 356569, 191566, 87441, 8219157, 8375553, 8029697,
		8026188, 8193863, 295873, 7906281, 487687, 8363474, 386621,
		282726, 8373831, 50680, 8239505, 7912018, 493972, 8335677,
		8079840, 251210, 263667, 221541, 41291, 88028, 8373098,
		505241, 7981448, 8308113, 299485, 428036, 93865, 90428,
		392003, 80833, 7975521, 336649, 7950328, 8049195, 8332757,
		8205291, 8178296, 7911197, 7925805, 519154, 60176, 54121,
		222738, 464285, 8022604, 8174235, 7856202, 8291898, 473254,
		8106411, 7943812, 267650, 7958173, 372387, 409597, 204263,
		477847, 83925, 111791,
	}
	for i := 0; i < 64; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniformLeGamma1(&p, &seed, 30000)
	p.Normalize()
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}
