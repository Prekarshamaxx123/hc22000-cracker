#include <cuda_runtime.h>
#include <stdio.h>

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long long ull;

#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

__device__ void sha1_block(uint *state, const uchar *block) {
    uint w[16];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint)block[i*4]<<24)|((uint)block[i*4+1]<<16)|
               ((uint)block[i*4+2]<<8)|(uint)block[i*4+3];
    }
    uint a=state[0],b=state[1],c=state[2],d=state[3],e=state[4];
    #define R(i,f,k) { uint _t=ROTL(a,5)+(f)+e+k+w[i]; e=d;d=c;c=ROTL(b,30);b=a;a=_t; }
    #define W(i) (ROTL(w[(i-3)%16]^w[(i-8)%16]^w[(i-14)%16]^w[(i-16)%16],1))
    #define R2(i) { w[i%16]=W(i); uint _t=ROTL(a,5)+w[i%16]; _t+=e; _t+=(i<40?(i<20?(b&c)|(~b&d):b^c^d):(i<60?(b&c)|(b&d)|(c&d):b^c^d)); _t+=(i<20?0x5A827999U:i<40?0x6ED9EBA1U:i<60?0x8F1BBCDCU:0xCA62C1D6U); e=d;d=c;c=ROTL(b,30);b=a;a=_t; }
    R(0,(b&c)|(~b&d),0x5A827999U);R(1,(b&c)|(~b&d),0x5A827999U);R(2,(b&c)|(~b&d),0x5A827999U);R(3,(b&c)|(~b&d),0x5A827999U);
    R(4,(b&c)|(~b&d),0x5A827999U);R(5,(b&c)|(~b&d),0x5A827999U);R(6,(b&c)|(~b&d),0x5A827999U);R(7,(b&c)|(~b&d),0x5A827999U);
    R(8,(b&c)|(~b&d),0x5A827999U);R(9,(b&c)|(~b&d),0x5A827999U);R(10,(b&c)|(~b&d),0x5A827999U);R(11,(b&c)|(~b&d),0x5A827999U);
    R(12,(b&c)|(~b&d),0x5A827999U);R(13,(b&c)|(~b&d),0x5A827999U);R(14,(b&c)|(~b&d),0x5A827999U);R(15,(b&c)|(~b&d),0x5A827999U);
    #undef R
    R2(16);R2(17);R2(18);R2(19);R2(20);R2(21);R2(22);R2(23);R2(24);R2(25);R2(26);R2(27);R2(28);R2(29);R2(30);R2(31);
    R2(32);R2(33);R2(34);R2(35);R2(36);R2(37);R2(38);R2(39);R2(40);R2(41);R2(42);R2(43);R2(44);R2(45);R2(46);R2(47);
    R2(48);R2(49);R2(50);R2(51);R2(52);R2(53);R2(54);R2(55);R2(56);R2(57);R2(58);R2(59);R2(60);R2(61);R2(62);R2(63);
    R2(64);R2(65);R2(66);R2(67);R2(68);R2(69);R2(70);R2(71);R2(72);R2(73);R2(74);R2(75);R2(76);R2(77);R2(78);R2(79);
    #undef R2
    #undef W
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;state[4]+=e;
}

__device__ void sha1_full(const uchar *msg, uint len, uchar *digest, uchar *buf) {
    uint state[5]={0x67452301U,0xEFCDAB89U,0x98BADCFEU,0x10325476U,0xC3D2E1F0U};
    uint off;
    for (off=0;off+64<=len;off+=64) sha1_block(state,msg+off);
    uint rem=len-off;
    for (uint i=0;i<rem;i++) buf[i]=msg[off+i];
    buf[rem]=0x80U;
    if (rem>=56) {
        for (uint i=rem+1;i<64;i++) buf[i]=0; sha1_block(state,buf);
        for (uint i=0;i<56;i++) buf[i]=0;
    } else { for (uint i=rem+1;i<56;i++) buf[i]=0; }
    ull bits=(ull)len*8;
    for (int i=0;i<8;i++) buf[56+i]=(uchar)(bits>>(56-i*8));
    sha1_block(state,buf);
    for (int i=0;i<5;i++) {
        digest[i*4]=(uchar)(state[i]>>24);digest[i*4+1]=(uchar)(state[i]>>16);
        digest[i*4+2]=(uchar)(state[i]>>8);digest[i*4+3]=(uchar)(state[i]);
    }
}

__device__ void hmac_sha1(const uchar *key, uint klen, const uchar *msg, uint mlen, uchar *mac, uchar *scratch) {
    uchar *ipad=scratch,*opad=scratch+64,*inner=scratch+128,*idig=scratch+260,*buf=scratch+280;
    for (int i=0;i<64;i++) { uchar k=(i<(int)klen)?key[i]:0; ipad[i]=k^0x36U; opad[i]=k^0x5CU; }
    for (int i=0;i<64;i++) inner[i]=ipad[i];
    for (uint i=0;i<mlen;i++) inner[64+i]=msg[i];
    sha1_full(inner,64+mlen,idig,buf);
    for (int i=0;i<64;i++) inner[i]=opad[i];
    for (int i=0;i<20;i++) inner[64+i]=idig[i];
    sha1_full(inner,64+20,mac,buf);
}

__device__ void pbkdf2(const uchar *pw, uint pwlen, const uchar *salt, uint slen, uint iter, uint dklen, uchar *out, uchar *scratch) {
    uchar *sb=scratch,*u=scratch+68,*t=scratch+88,*hs=scratch+108;
    uint blk=(dklen+19)/20;
    for (uint b=1;b<=blk;b++) {
        for (uint i=0;i<slen;i++) sb[i]=salt[i];
        sb[slen]=(uchar)(b>>24);sb[slen+1]=(uchar)(b>>16);
        sb[slen+2]=(uchar)(b>>8);sb[slen+3]=(uchar)(b);
        hmac_sha1(pw,pwlen,sb,slen+4,u,hs);
        for (int i=0;i<20;i++) t[i]=u[i];
        for (uint j=2;j<=iter;j++) {
            hmac_sha1(pw,pwlen,u,20,u,hs);
            for (int i=0;i<20;i++) t[i]^=u[i];
        }
        uint cl=(b==blk)?(dklen-(b-1)*20):20;
        for (uint i=0;i<cl;i++) out[(b-1)*20+i]=t[i];
    }
}

__global__ void crack_kernel(
    const uchar *charset, uint charset_len, uint pw_length,
    const uchar *ssid, uint ssid_len,
    const uchar *target, const uchar *ap_mac, const uchar *sta_mac,
    ull start, volatile int *found, uchar *found_pw
) {
    ull idx=start+blockIdx.x*blockDim.x+threadIdx.x;
    if (*found) return;

    uchar pw[32];
    ull tmp=idx;
    for (int i=(int)pw_length-1;i>=0;i--) { pw[i]=charset[tmp%charset_len]; tmp/=charset_len; }

    uchar pmk[32],scr[512];
    pbkdf2(pw,pw_length,ssid,ssid_len,4096,32,pmk,scr);

    uchar pm_msg[20];
    pm_msg[0]=80;pm_msg[1]=77;pm_msg[2]=75;pm_msg[3]=32;
    pm_msg[4]=78;pm_msg[5]=97;pm_msg[6]=109;pm_msg[7]=101;
    for (int i=0;i<6;i++){pm_msg[8+i]=ap_mac[i];pm_msg[14+i]=sta_mac[i];}

    uchar pr[20];
    hmac_sha1(pmk,32,pm_msg,20,pr,scr+128);

    int ok=1;
    for (int i=0;i<16;i++) if (pr[i]!=target[i]){ok=0;break;}
    if (ok) {
        *found=1;
        for (uint i=0;i<pw_length;i++) found_pw[i]=pw[i];
    }
}

extern "C" {

int cuda_crack(
    const char *charset, int charset_len,
    const uchar *ssid, int ssid_len,
    const uchar *target,
    const uchar *ap_mac, const uchar *sta_mac,
    int pw_length, ull start, ull count,
    char *found_pw
) {
    uchar *d_charset, *d_ssid, *d_target, *d_ap, *d_sta;
    int *d_found;
    uchar *d_found_pw;

    cudaMalloc(&d_charset, charset_len);
    cudaMalloc(&d_ssid, ssid_len);
    cudaMalloc(&d_target, 16);
    cudaMalloc(&d_ap, 6);
    cudaMalloc(&d_sta, 6);
    cudaMalloc(&d_found, sizeof(int));
    cudaMalloc(&d_found_pw, 64);

    cudaMemcpy(d_charset, charset, charset_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_ssid, ssid, ssid_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_target, target, 16, cudaMemcpyHostToDevice);
    cudaMemcpy(d_ap, ap_mac, 6, cudaMemcpyHostToDevice);
    cudaMemcpy(d_sta, sta_mac, 6, cudaMemcpyHostToDevice);

    int zero=0;
    cudaMemcpy(d_found, &zero, sizeof(int), cudaMemcpyHostToDevice);

    int blockSize = 128;
    int gridSize = (count + blockSize - 1) / blockSize;
    if (gridSize > 65535) gridSize = 65535;

    ull remaining = count;
    ull chunk_start = start;
    while (remaining > 0 && gridSize > 0) {
        int threads = blockSize * gridSize;
        if (threads > remaining) {
            gridSize = (remaining + blockSize - 1) / blockSize;
            threads = blockSize * gridSize;
        }

        crack_kernel<<<gridSize, blockSize>>>(
            d_charset, charset_len, pw_length,
            d_ssid, ssid_len,
            d_target, d_ap, d_sta,
            chunk_start, d_found, d_found_pw
        );
        cudaDeviceSynchronize();

        int found_val;
        cudaMemcpy(&found_val, d_found, sizeof(int), cudaMemcpyDeviceToHost);
        if (found_val) {
            uchar pw[64]={0};
            cudaMemcpy(pw, d_found_pw, 64, cudaMemcpyDeviceToHost);
            for (int i=0;i<64;i++) found_pw[i]=(char)pw[i];
            cudaFree(d_charset);cudaFree(d_ssid);cudaFree(d_target);
            cudaFree(d_ap);cudaFree(d_sta);cudaFree(d_found);cudaFree(d_found_pw);
            return 1;
        }

        remaining -= threads;
        chunk_start += threads;
        if (remaining < threads) {
            gridSize = (remaining + blockSize - 1) / blockSize;
        }
    }

    cudaFree(d_charset);cudaFree(d_ssid);cudaFree(d_target);
    cudaFree(d_ap);cudaFree(d_sta);cudaFree(d_found);cudaFree(d_found_pw);
    return 0;
}

} // extern "C"
