package vendorintegrity

import (
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

const expectedFileManifest = `d114417e6082366cf080e6fb17760074c2847ad38bf9b2f04f8c73fa413ae8a9	862	modules.txt
d6616c2fb2fb2d14d4fa886057286cab81f877fd945638618bc9966203fc0a84	889	filippo.io/edwards25519/doc.go
cd82641c426a8c294e2b80d746116eb1b1707bfb980199599ef4cbb94cbb25b3	10523	filippo.io/edwards25519/edwards25519.go
e646542ebc4c8f751de2ca30d98d66a6289d5885b91ed3a3f44327b1d937dd24	11765	filippo.io/edwards25519/extra.go
2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067	1479	filippo.io/edwards25519/LICENSE
47729255f459cabf394b7b0de04e15d5b31b224b1b3a1dd93bde7182b219237d	1466	filippo.io/edwards25519/pull.sh
39760d8b144d127d4b3be241cf93f7c12fbc1d0b6d3ac4e2da8f0ba68a3b1532	1378	filippo.io/edwards25519/README.md
a9bc7ecfd7715467b3fcb3924ecddb9f4200324c1db4d1f804c4fa3e94fe896f	36460	filippo.io/edwards25519/scalar_fiat.go
e4aebdd46ca174b66c9bb782aae062020f6984a20434c9f119ce271a6f30abce	11611	filippo.io/edwards25519/scalar.go
11f525c854f8e9738a5779adf61d8b3cb39067bd9ccad6a908355811242ecc1f	6444	filippo.io/edwards25519/scalarmult.go
3ca8e777db7ff27a99c2994254ea7afe4ccf29de8bb1f0f6b422f4b3f0c9c616	3753	filippo.io/edwards25519/tables.go
3f3d670d4da11ac2e68a8dfd69d869f955ea9a85264cf88ee55184e61f74ba2e	319	filippo.io/edwards25519/field/fe_amd64_noasm.go
1d1ea6a61ee950e19ce37b8be7b9250e962a922fb768bfc64cfbca63952af4d1	395	filippo.io/edwards25519/field/fe_amd64.go
affcfc732685da135acea57e6c0a09d893ad21547128b67c2e9583c23654f7c7	6015	filippo.io/edwards25519/field/fe_amd64.s
8fda2b521aaa3e7506fd4556f82d115068222e5843a0822ec75376bfa7216024	1784	filippo.io/edwards25519/field/fe_extra.go
75d213650f76b7c5501202bf5cae1f0cdc1f84fbaa8bed5f93c0109189e01dba	9147	filippo.io/edwards25519/field/fe_generic.go
2ba45341ad3167343c18812b92d0fcddfad17e159e0770622a30fd190c565f06	12259	filippo.io/edwards25519/field/fe.go
b4a2963bc20a9f02d67176c5632f17647503fec12eadfb8cf5264b0163c8957f	170	github.com/santhosh-tekuri/jsonschema/v6/.gitmodules
71f530b540913cd5e448381b085f3ab29576b33a2dfdd7d36822f7a121268201	75	github.com/santhosh-tekuri/jsonschema/v6/.golangci.yml
2813035df78f20cb817ccc572f61d240bd33d5f429d7d2a9c60124767d7db6d5	201	github.com/santhosh-tekuri/jsonschema/v6/.pre-commit-hooks.yaml
70866caca3a796301c74dfb2a963d53809c0b94c3dcbcc7f8ac5f8f480856b76	7942	github.com/santhosh-tekuri/jsonschema/v6/compiler.go
06ab11a570b088691c5526f7cff82879532ca4d07b3438ea1d2903cd426d8ec2	1133	github.com/santhosh-tekuri/jsonschema/v6/content.go
bb436dc7f6070066e621cb1bb4b0da0a7e1fdf09e8563443885713cda2cf7dd2	7979	github.com/santhosh-tekuri/jsonschema/v6/draft.go
87bd46648c3da990a12e27ae3eedb13346a1ece32ecd264d760d0e3ac04b3320	16977	github.com/santhosh-tekuri/jsonschema/v6/format.go
1d10f5de713051a5ffddab1510d1b08e8749b785dd620be203ddbfef92046365	98	github.com/santhosh-tekuri/jsonschema/v6/go.work
7d86ff007b9ee9c4bd20cb86588cf4d6e040345ea8109ea21f82a79145d8965c	342	github.com/santhosh-tekuri/jsonschema/v6/go.work.sum
c8858a5a76440bbca484e134cf7df46385d090dd18b2c58e650f939258802e5b	10141	github.com/santhosh-tekuri/jsonschema/v6/LICENSE
e5c2fb9641a9170e1110f12ba4c05d427ba5a947f5d83762862b937492d15071	5268	github.com/santhosh-tekuri/jsonschema/v6/loader.go
d68bace1a42c152a3686c82342c584aedcab9f0aa259e9c70701e7a0bf02e99f	11445	github.com/santhosh-tekuri/jsonschema/v6/objcompiler.go
30e8122d7a3e60ac521c9d78f2bb41632643ad31d0a459c3ab22215d2c3992d4	5310	github.com/santhosh-tekuri/jsonschema/v6/output.go
c1feda050097cb60562392eb3381cf7793c90800cc5495fdfda6193003b1d34f	2411	github.com/santhosh-tekuri/jsonschema/v6/position.go
e04f71e6bab7f544a8068b2ff4c71038a4ff78a4f7c0c914fd9fd1235359c9e0	4330	github.com/santhosh-tekuri/jsonschema/v6/README.md
855a6f675eef7fa50308da6d346151a6403747b00a2e1a9011e99bf1f2df78bd	4369	github.com/santhosh-tekuri/jsonschema/v6/root.go
6e84cb61bbb143e334c5c587295064bac0eeadecec73c4e5685aaa67d461bdc2	6164	github.com/santhosh-tekuri/jsonschema/v6/roots.go
cce55c5e4bdcef1b702537f30cf6d2356a08328b215a103aac9e61ba59ea3318	5516	github.com/santhosh-tekuri/jsonschema/v6/schema.go
cd6768313dbb08506f1438bef2db307eddaaab178b06e46d6973265101ca44c5	9443	github.com/santhosh-tekuri/jsonschema/v6/util.go
6474becfb427adc759f9ee616f709eae4342385a06030fee1107b38c6711cfb8	22146	github.com/santhosh-tekuri/jsonschema/v6/validator.go
1cc9406daefa2bf8d95f07640f9591b17bb18578395bc5a09a48b9402f74428a	3100	github.com/santhosh-tekuri/jsonschema/v6/vocab.go
4141eba8d0aa75661744cb0a1f133cd7e85268da2b2b8cc3f3bf7af5f3629167	12787	github.com/santhosh-tekuri/jsonschema/v6/kind/kind.go
9591bb2cf00ab32193870cb6a2ca4c32ae89e254af154f4e971c61a6ee82da03	1529	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/schema
c18c9d8880297184560f6d82a2fc035211630474d1b2547feaccf221b9786211	1511	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/meta/applicator
03d8e25955252927e34016e03f51297475ace9de4551839d1b54c9f5736ff6d6	464	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/meta/content
a3dfd7891bc6ec4a0147289bc99de4cec2a84ff542b2edfac6de95f402907503	1146	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/meta/core
708bad3c6cee27e8c0d5cbf26e41eef6f1c56fec5f91b0eaa471ef2fc521d463	363	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/meta/format
a72a0fbc2272d9effcc71a159f9c92f0ef4417c0f1677f515767de77b5238a0a	689	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/meta/meta-data
e1a3128accd99efc4cc198545479eae1548ce303a96810c1a0a28f022f0489a2	2107	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/meta/validation
0080fa14a942b09f436c55257d1e379c5cb2551f732e678fa06e8009fb7c2582	2076	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/schema
3b4baccc121371207bcb2d3137b9b93a251b2029df85ecda0ca625ecd1ab9b30	1427	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/applicator
3be161f2e963fbb8f09a756cc3b02adbe5375fe71020b959213e2b58e92f5886	479	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/content
ea945e11e766783c05ef2bda8958ef2b64746430b6b7475c1915babbd6c01264	1302	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/core
59cb0d1d59c430d5d691f4712dc2b4d09ba6dafcb90f7ce14b8f11b07340a6c6	419	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/format-annotation
4c45dfbf72b09ec8b0cd6c8086c259bd4b1d68b86138d886e8191fc0189270b8	416	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/format-assertion
e070588fd8fac3a0b4bed1dbe1f576ccdb2e32ade3b46bd590150d0b15506859	722	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/meta-data
cd2e94b6154c7ab9ee90f8bfa8d8addf9f6ae75a58fc090099605401303653cb	472	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/unevaluated
000831f2fffd6927b25f9d601e6f0cc6bc8d51ed6c967d63c1449d1f76f8568a	2202	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta/validation
5e4a46b433800681b8da4911df61cd72212d5bce2839e1c772e2b99a89fbbf09	3251	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft-04/schema
bf7460259b94e8291eaeec1b077f98caff3d16df17ee2a99208f74f1412c4932	3195	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft-06/schema
943da3dc9a29dbfbd325aec2ca01cfd6304a1cd53fde2c9775bcca6523f6410e	3656	github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft-07/schema
2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067	1479	golang.org/x/crypto/LICENSE
96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc	1303	golang.org/x/crypto/PATENTS
f370186a863f5ef09589b842c688747c480dfd4d3d6bb89661e08de78ed49bb8	7503	golang.org/x/crypto/blake2b/blake2b.go
1a2952821dcf30e5f49a9eec1091ba5f74d6f900cde45eb842bdf36204430982	905	golang.org/x/crypto/blake2b/blake2bAVX2_amd64.go
6f1cda9e75d4ce889fcb834cb8733bda26a38db4b842c1475795ca7ffb5cf59c	24237	golang.org/x/crypto/blake2b/blake2bAVX2_amd64.s
5d1ec2a6232c3aa8d2c6abc8577f56c4cf6d9e0b5d443136f823a82628f24c6d	8558	golang.org/x/crypto/blake2b/blake2b_amd64.s
3ca806fe8939d7688d4dfa70003bef7ff55e66088176b6c6b794fb32fe02725f	4131	golang.org/x/crypto/blake2b/blake2b_generic.go
d7e3c0c71f323f0226badb07a0a04daba5b40e7d5f8d31ac622608c7d6761f25	328	golang.org/x/crypto/blake2b/blake2b_ref.go
0bbc2fbd298ee663cebf28716bd1946682e96abad982fc1a54e2396cb4ca596b	4135	golang.org/x/crypto/blake2b/blake2x.go
f010131c5e272dde27a5d1d30ce1329d681fdd74b5f5025d197c29448e57deae	594	golang.org/x/crypto/blake2b/register.go
2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067	1479	golang.org/x/sys/LICENSE
96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc	1303	golang.org/x/sys/PATENTS
5a50f8f52ea89a7c638bdd6798f576523ecfc1e4ec2cb657d445f1a7dc0dfab2	407	golang.org/x/sys/cpu/asm_aix_ppc64.s
825146fd4557b1cbd8161fa28bb4be8820089848d695316edeecb7fd5a551f8a	1868	golang.org/x/sys/cpu/byteorder.go
2cde798de4d6010a7faf9bd5e0c6abcd9a57b9ca0bdd82ca58d38b7c8027cf65	12364	golang.org/x/sys/cpu/cpu.go
1e9265c7703fe4b8b2bd6813e05f2fc15a83eb60e237dcafa0911b5b19a7e25f	605	golang.org/x/sys/cpu/cpu_aix.go
23e6d65d2ba6bf988f6413643cb336b49b438b2b15659c0b22c2d0c63a25e3c0	2163	golang.org/x/sys/cpu/cpu_arm.go
7af15eb3d3f406ce6ac3cfe027295dc8485e7630c8214d7172969f8426649827	3767	golang.org/x/sys/cpu/cpu_arm64.go
6fc0c6ee0dcf741981018271639085f94e91cd955207ff6acc03a1ebbdc16c83	758	golang.org/x/sys/cpu/cpu_arm64.s
6316b8b49d85239203bc4b8e60617a4420bb3f4769a30017128fd62293688e9e	256	golang.org/x/sys/cpu/cpu_gc_arm64.go
9af08f2d1f95402635813d6303faae72ddd1218fc27115252002282da415f7e8	674	golang.org/x/sys/cpu/cpu_gc_s390x.go
21711aec00bd43881cbf8b233763adea3db57f17631eb303ec706b6948c43263	499	golang.org/x/sys/cpu/cpu_gc_x86.go
db9c59162435505021c13a5f0a3c78cb4acbf611032746fa5c637e487789511b	299	golang.org/x/sys/cpu/cpu_gccgo_arm64.go
89f09aa36fdb1fef1a4ec171178cc12daf4f49e6ee368fec496c482d04ddf145	1029	golang.org/x/sys/cpu/cpu_gccgo_s390x.go
50585132982aa1dda61a887bb62f468a1a843cf1993d59a4b0fe6ca2e8a5c8f7	1095	golang.org/x/sys/cpu/cpu_gccgo_x86.c
63076f1a1b8669db58e902ddd9653fcccce44fe046f0c62574224c2a2d2d6729	795	golang.org/x/sys/cpu/cpu_gccgo_x86.go
cf0f4c7211c4cc912689fecbd30bd4747b6dadf577b065ac03823d74ae1ac870	322	golang.org/x/sys/cpu/cpu_linux.go
5c2f68fd8e53218eb96b8d67375564242a6bf825021a4ecbc8347af6f47898c0	1393	golang.org/x/sys/cpu/cpu_linux_arm.go
ee480c4f8102228249f8389f96b2f6b869504e09fbf80b245cd9144df9ae3050	3437	golang.org/x/sys/cpu/cpu_linux_arm64.go
2527fa939ae3ba4ff7a7a5190c865cdde199d079e5f25b7aa52b1b56e4e11016	480	golang.org/x/sys/cpu/cpu_linux_mips64x.go
7dc9069abfc5566ac4a0c2642cce5650d86fea693f62af356ef536915e1573ec	282	golang.org/x/sys/cpu/cpu_linux_noinit.go
01d1a98f48bec3bbb204e88898ba6b5441d30671cb502790e9091471d25d304a	775	golang.org/x/sys/cpu/cpu_linux_ppc64x.go
290f658b0d8e7e9dd93d3b908cd202f13b3a4f228071d4211f4e1947050dbbcc	890	golang.org/x/sys/cpu/cpu_linux_s390x.go
9e9698be08b0bd12c6f33f9e470c8214b0c597d339e211f4432292a8fcaad76a	242	golang.org/x/sys/cpu/cpu_loong64.go
77a333aebca444ef9f718d27df30422a9ac88cba29add1029c30d3dc1c6dc781	320	golang.org/x/sys/cpu/cpu_mips64x.go
35bb6ba0d168ee41f3763110d65e39e8f6271995b59e6422dc65690fb69e2a9a	248	golang.org/x/sys/cpu/cpu_mipsx.go
b250e2406e45f0c972605266c3d67dd7a6ad614cb0fba5467d87facf62464436	4359	golang.org/x/sys/cpu/cpu_netbsd_arm64.go
681c260436ffe0d3d591bc99e9e08a3218e0017589552a7f6a374fcd4a54aad8	1702	golang.org/x/sys/cpu/cpu_openbsd_arm64.go
5ab9396eff64294fd703389dfae36d4d794f6261c79b6cbfc347699b38f361cc	376	golang.org/x/sys/cpu/cpu_openbsd_arm64.s
54da156f719d6aee6e14693c79a062680db425f5580d6222d56e57c53e228ca6	218	golang.org/x/sys/cpu/cpu_other_arm.go
615305a105429a427461329ee47fe30ac1e0e7db93edb3a624a2d43069224290	241	golang.org/x/sys/cpu/cpu_other_arm64.go
f0ff8ddcebee1e3652369ff24d1f09c22702048266e0c64e0ebac908247c0829	256	golang.org/x/sys/cpu/cpu_other_mips64x.go
0baab277f0a08d9b958cd1dc3c06f35ebd63c453bfff47adb65e7bbdbf94cb97	285	golang.org/x/sys/cpu/cpu_other_ppc64x.go
f4595d128c37d0b779b788170d6e7976b0b488644b3df07774c0ffbfb4fac28c	243	golang.org/x/sys/cpu/cpu_other_riscv64.go
63aa31373ef16a2ca856ca2a1e54496d4cc91602ebf64bf5df99fbdfc334a896	360	golang.org/x/sys/cpu/cpu_ppc64x.go
04d8fc187abb0d1caea131cd5d49bff0aff2fa4174d19f05f9daba1b4c7a3c1c	241	golang.org/x/sys/cpu/cpu_riscv64.go
0abc36c54a82044ad48a406a2828e522f24b70247c922a79330cf8f616debbef	4993	golang.org/x/sys/cpu/cpu_s390x.go
2ab869aa3b38626aba388fa6db352a3be80f1efdfd2085bdf97c2ef594a5e777	2007	golang.org/x/sys/cpu/cpu_s390x.s
0da8add0ce546dfed3a844f94ce693137b6833712c016561f598e6d8b08c474e	439	golang.org/x/sys/cpu/cpu_wasm.go
ec2bf2e0967876cbb696c364160f7697a904b243e8160f4afc2f471e4ce0d37a	4969	golang.org/x/sys/cpu/cpu_x86.go
5ba35bcee387a818c370484f8e3a09b6eef842d7b5b110615dd758cf5e29f30b	600	golang.org/x/sys/cpu/cpu_x86.s
ff82e534d4d81726e13f34919386becdcb65cb9fc24c0f5835314e00fe13070d	223	golang.org/x/sys/cpu/cpu_zos.go
53b684a51586ff413570961780bea6526a6eab2568dce27c15efdf0d8e421d05	643	golang.org/x/sys/cpu/cpu_zos_s390x.go
005d2761cef8d501304f73be92a7f43174bf738a380c9d5d7bc0cac926075f57	397	golang.org/x/sys/cpu/endian_big.go
c6bc70c372d9e1fe86fcf295f406b17bf04bf8d1af25c2456f58520cdaef3be9	433	golang.org/x/sys/cpu/endian_little.go
4101df793fddf76dfae477f917928008bc4a797446cd4ad44cde6e906c3f8713	1510	golang.org/x/sys/cpu/hwcap_linux.go
2a7609201edd3538f89942ea8a32307c377d7937f6623bcba98d328986010e27	1029	golang.org/x/sys/cpu/parse.go
dfdf71a1c8d94e7cc44117cadb1cf6f66fa2e8cdfb873dd5f1d85831d19841aa	1113	golang.org/x/sys/cpu/proc_cpuinfo_linux.go
d898ace395866bed261d403c8cd0ea6eab6d6d77f52042204957e389c38938cf	393	golang.org/x/sys/cpu/runtime_auxv.go
6eee9d1a593dce53d22545dc5d5f6ed9127a43e6568ef5f5521920946510d445	357	golang.org/x/sys/cpu/runtime_auxv_go121.go
a384f5e0e1f961a15295f30078e8c8cf16ec28672b659b7ff80829ccf8a2a848	726	golang.org/x/sys/cpu/syscall_aix_gccgo.go
33f76a8da28ee51d3db32944949fc2ddcb9870ba0f2d22d29732dfcf2a6ba119	988	golang.org/x/sys/cpu/syscall_aix_ppc64_gc.go
2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067	1479	golang.org/x/text/LICENSE
96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc	1303	golang.org/x/text/PATENTS
1c4510a2729ea9cc0fbf2aa7c68dc1ffdaf9bd10a9cfd9b504cda6dd5ae6e7df	1947	golang.org/x/text/feature/plural/common.go
3529fc66dc4316bef2e6312a882e2f38f49d4d2b8b4e0dff334b8ff146d64ea2	6453	golang.org/x/text/feature/plural/message.go
ab4d2a38f105f3aded86e4512d27e04d5179fe3391cc2bd3af811d4fbb3f38c5	7509	golang.org/x/text/feature/plural/plural.go
51f97e1fcadf37a6f331d5f8554e2c42d51a226a2486d59ceb55f0f3c7643de2	22621	golang.org/x/text/feature/plural/tables.go
cf0cafa0e1c996fedce38d955344a905cfd62711efa78e9d90d615d738e084fe	1040	golang.org/x/text/internal/internal.go
44fba33275128b0a885cb737eee4765567a35a1d2656de873680534bb37f7243	1912	golang.org/x/text/internal/match.go
ddbdb3a883da9521a764567eee51f8be4b7b3fdda479891167c374019bac76be	13906	golang.org/x/text/internal/catmsg/catmsg.go
51f791bf25ff62bd20bdcf95483603cb97457e9162a180eab057fd33f3990848	10627	golang.org/x/text/internal/catmsg/codec.go
38e2606b6d44edc7685e1bd7784c750d1ec3e38f9db336ed79e70de750b8ed2a	1493	golang.org/x/text/internal/catmsg/varint.go
b4843ba734004c0db278995f9a58be5d36d51f000f0413f7420116e24ad55cbe	1207	golang.org/x/text/internal/format/format.go
a793faa9666b27cb8bf92a703741c446b802d3ed7921622cf5050f26822f3479	8701	golang.org/x/text/internal/format/parser.go
68089abad3eed7b2559bb97510355e900a6ef2e1fac7ff89364bda9c50a2acba	334	golang.org/x/text/internal/language/common.go
2d121c703729c5fbd5f3f13fd568af142ca8fde0f01a07e1874df22dbaadde98	853	golang.org/x/text/internal/language/compact.go
7657b95eac8448d5d2273c048d316dde3ac0e49ac058487a69b2b990ebc7f8ef	3881	golang.org/x/text/internal/language/compose.go
8c8238012deb1b3c42820c755343db1bc326dc5cbddfcc24f97abbb7e0c6cee1	730	golang.org/x/text/internal/language/coverage.go
19a0ccf7635fd3dbad3766d953996df5d1c24a367e44c49200ab6ec3023fc871	17174	golang.org/x/text/internal/language/language.go
8f0ac8780f89d5c2b29b98fd599269b445d7bb612a7948c9e97d425424b5ea38	12387	golang.org/x/text/internal/language/lookup.go
711e9c548516929762f0636a69788ba6eed6ed10bfb47634f3b5d5a1f26a1547	5824	golang.org/x/text/internal/language/match.go
0c884b51bb83d3633a51f16e90c7dbaf45c301a449e366df591eda11a3000972	15241	golang.org/x/text/internal/language/parse.go
876a73fb8b8fffd239efa592ffdf903c25757b4d17b715fc80d7aee8db2b985e	156627	golang.org/x/text/internal/language/tables.go
21041c1c1982b12db6f523a4feb58746dac3e2c71e8dcf9f76ac5807cd809099	1211	golang.org/x/text/internal/language/tags.go
e154aa511d328fd47a9c9fc1115d9c92be2d385e885ae65c5e348ec1d5844ead	1707	golang.org/x/text/internal/language/compact/compact.go
1d49845ec8c93b000391718e3127c0979c054186570805fce27f7fe167ad2c5d	7447	golang.org/x/text/internal/language/compact/language.go
57dc7b46cb5b6df81ed5764b338e1b463c183e3561427307c9d25fa876d9bdc7	6853	golang.org/x/text/internal/language/compact/parents.go
99415fb6642ebd291f825497d32e70ae32da8569815d8f4ef587664c6c5ce7d5	32128	golang.org/x/text/internal/language/compact/tables.go
e6f98b11ee9c2d5d4d51a5d810d4ea2eff0872a8d11b962979744899e020e12c	5651	golang.org/x/text/internal/language/compact/tags.go
bce013ed59651b693ccccf3c190b7c8662b28ed8f0073fae69ca23623639ee5a	1297	golang.org/x/text/internal/number/common.go
d6bf692abc29a75b74488afaa07885087871b8c85fdf1a7432a5e4d426bcd1d1	12105	golang.org/x/text/internal/number/decimal.go
fd1004c1afbe4fde93141b3d839d6a5eaf01c91cfcc7036be326e954962a7a92	13797	golang.org/x/text/internal/number/format.go
a9160873055c35ca027ade76d71708b195c7157ccb0cde579624e5eb22a757c0	4827	golang.org/x/text/internal/number/number.go
82e3b1ba7949cb165b3849190921366bf99d5d70b9bf756d5ae89517d3717f69	12292	golang.org/x/text/internal/number/pattern.go
5072f5ff5fd6f7570b7811dee6c2ba7c26669d3b0b953ab47007af00cb9c4dc5	894	golang.org/x/text/internal/number/roundingmode_string.go
a00837349bdfb503cfc549bfccf04fe54baf974dc5f5c6ebf375ac26cec43243	53037	golang.org/x/text/internal/number/tables.go
b14cd183aa7f94f7c46a55eb110506efc0ee535ffedfc38d68a4c3d1e25277b3	2083	golang.org/x/text/internal/stringset/set.go
97a27a6bfdd26d872e07d051fc27e622e1cd764943350e8bfa9cf0e2e13cc474	2415	golang.org/x/text/internal/tag/tag.go
d12716948854471a3536a04dc48736b0db0318ea6df61db236bc4ee0fe725375	4897	golang.org/x/text/language/coverage.go
4b97559b103832f3c5f22e80f2df0dd7394a469d945f79afad1654eb179fa63b	4340	golang.org/x/text/language/doc.go
3f2032f0367d83fb14772384d47119d27c2c427b277aa0a02913db59abe32bb0	19340	golang.org/x/text/language/language.go
b8a6b973391cba46899d079173cf0b1d3064f28bb79a11c3fdc65c089cbe23d3	25698	golang.org/x/text/language/match.go
c100309e93f15f7d36fcde02b598c146f4a4b011b6ba29676b9592d0753d71f5	7695	golang.org/x/text/language/parse.go
cb3c6aa474902c2728c47bcdebd5fcac0c6aa0f7e29934e984d46434c98ce716	14585	golang.org/x/text/language/tables.go
247c5ce419821c135a2751029c078cc6e1472c9896dd581d67a277449e54d968	5545	golang.org/x/text/language/tags.go
b5162478103e86e7f7b19e77e2cbb56d1ec4fd80687649e4cd811ce9138ad71a	1162	golang.org/x/text/message/catalog.go
84cd131fb24ca905aa697e58f1f98d398b42efeda852e7f389cfefe65581ef91	3577	golang.org/x/text/message/doc.go
b8c30f1692d4e33bdf6eec0b8f1b388c26bd14d5a950b0abb12673fab067ea07	12261	golang.org/x/text/message/format.go
3e9d3f779b7a0e6b579518892facf266b3a1f70a8bd99980fa8d262fa3b7e5cb	4700	golang.org/x/text/message/message.go
b77eddda2754c15c464855b6fb5cdd704586a5fbd7a3c372c8121aea582298d4	23802	golang.org/x/text/message/print.go
f5d697a9316fe2a91034e634961bf0b8fc67570077b7835d9e3974f912e267d8	13505	golang.org/x/text/message/catalog/catalog.go
97d966a0b588ac0008d74fde9eb23ac21650cd7863ebde257387f8adc18c0298	2816	golang.org/x/text/message/catalog/dict.go
2ead529c96e990f6d2599d0433ae4e786c36fabe201ec4d1b2eca6cedc62225c	440	golang.org/x/text/message/catalog/go19.go
1bca2789d5508a8eada969f7297422ffb1f832f7e278ab746737889a5188832d	565	golang.org/x/text/message/catalog/gopre19.go`

const expectedDirectoryManifest = `filippo.io
github.com
golang.org
filippo.io/edwards25519
filippo.io/edwards25519/field
github.com/santhosh-tekuri
github.com/santhosh-tekuri/jsonschema
github.com/santhosh-tekuri/jsonschema/v6
github.com/santhosh-tekuri/jsonschema/v6/kind
github.com/santhosh-tekuri/jsonschema/v6/metaschemas
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft-04
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft-06
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft-07
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2019-09/meta
github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft/2020-12/meta
golang.org/x
golang.org/x/text
golang.org/x/text/feature
golang.org/x/text/internal
golang.org/x/text/language
golang.org/x/text/message
golang.org/x/text/feature/plural
golang.org/x/text/internal/catmsg
golang.org/x/text/internal/format
golang.org/x/text/internal/language
golang.org/x/text/internal/number
golang.org/x/text/internal/stringset
golang.org/x/text/internal/tag
golang.org/x/text/internal/language/compact
golang.org/x/text/message/catalog
golang.org/x/crypto
golang.org/x/crypto/blake2b
golang.org/x/sys
golang.org/x/sys/cpu`

var expectedFiles = mustParseFileManifest(expectedFileManifest)

var expectedDirectories = mustParseDirectoryManifest(expectedDirectoryManifest)

var expectedMetadata = []fileRecord{
	{path: "go.mod", size: 265, sha256: "48b8c446099002e13b06c960e2a4ee409fe28b075c44b213d9ab547dcf754759"},
	{path: "go.sum", size: 1004, sha256: "e33cba351e5d592f7dc067ae3d189a04fec94e9ba182d1d06a242dd0805fe692"},
	{path: "vendor/modules.txt", size: 862, sha256: "d114417e6082366cf080e6fb17760074c2847ad38bf9b2f04f8c73fa413ae8a9"},
}

func mustParseFileManifest(manifest string) []fileRecord {
	lines := strings.Split(manifest, "\n")
	records := make([]fileRecord, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for index, line := range lines {
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			panic(fmt.Sprintf("vendor lock file manifest line %d is malformed", index+1))
		}
		digest, sizeText, name := fields[0], fields[1], fields[2]
		if len(digest) != sha256HexLength {
			panic(fmt.Sprintf("vendor lock digest for %q has invalid length", name))
		}
		if _, err := hex.DecodeString(digest); err != nil || digest != strings.ToLower(digest) {
			panic(fmt.Sprintf("vendor lock digest for %q is not lowercase SHA-256", name))
		}
		size, err := strconv.ParseInt(sizeText, 10, 64)
		if err != nil || size < 0 {
			panic(fmt.Sprintf("vendor lock size for %q is invalid", name))
		}
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.Contains(name, "\\") {
			panic(fmt.Sprintf("vendor lock path %q is not canonical", name))
		}
		if _, ok := seen[name]; ok {
			panic(fmt.Sprintf("vendor lock path %q is duplicated", name))
		}
		seen[name] = struct{}{}
		records = append(records, fileRecord{path: name, size: size, sha256: digest})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].path < records[j].path })
	if len(records) != ExpectedFileCount {
		panic(fmt.Sprintf("vendor lock has %d file records; want %d", len(records), ExpectedFileCount))
	}
	return records
}

func mustParseDirectoryManifest(manifest string) []string {
	directories := strings.Split(manifest, "\n")
	seen := make(map[string]struct{}, len(directories))
	for _, name := range directories {
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.Contains(name, "\\") {
			panic(fmt.Sprintf("vendor lock directory %q is not canonical", name))
		}
		if _, ok := seen[name]; ok {
			panic(fmt.Sprintf("vendor lock directory %q is duplicated", name))
		}
		seen[name] = struct{}{}
	}
	sort.Strings(directories)
	return directories
}
