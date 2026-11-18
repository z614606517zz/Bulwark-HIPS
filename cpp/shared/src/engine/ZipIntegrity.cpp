#include "bulwark/engine/ZipIntegrity.h"
#include "miniz.h"
#include <QElapsedTimer>
#include <array>

namespace bulwark::engine {
namespace {
quint16 u16(const QByteArray& b, qsizetype p) {
    return quint16(quint8(b[p])) | quint16(quint8(b[p+1]) << 8);
}
quint32 u32(const QByteArray& b, qsizetype p) {
    return quint32(u16(b,p)) | (quint32(u16(b,p+2)) << 16);
}
quint32 crc(const QByteArray& b) {
    static const auto table = [] {
        std::array<quint32,256> out{};
        for (quint32 i=0;i<256;++i) {
            quint32 v=i;
            for (int j=0;j<8;++j) v=(v>>1)^((v&1)?0xedb88320U:0U);
            out[i]=v;
        }
        return out;
    }();
    quint32 result=0xffffffffU;
    for (const char c : b) result=(result>>8)^table[(result^quint8(c))&255];
    return result^0xffffffffU;
}
}
FileIntegrity ZipIntegrity::verify(const QByteArray& b) {
    using I=FileIntegrity;
    if (b.size()>maxArchiveBytes) return I::Unsupported;
    if (b.size()<22) return I::Invalid;
    QElapsedTimer timer; timer.start();
    qsizetype end=-1;
    for (qsizetype i=b.size()-22;i>=qMax<qsizetype>(0,b.size()-65557);--i)
        if (u32(b,i)==0x06054b50 && i+22+u16(b,i+20)==b.size()) { end=i; break; }
    if (end<0) return I::Invalid;
    const quint16 count=u16(b,end+10);
    const quint32 cdSize=u32(b,end+12), cdOffset=u32(b,end+16);
    if (u16(b,end+4)||u16(b,end+6)||u16(b,end+8)!=count||count==0xffff
        || cdSize==0xffffffffU||cdOffset==0xffffffffU) return I::Unsupported;
    if (count>256) return I::Unsupported;
    const quint64 cdEnd=quint64(cdOffset)+cdSize;
    if (cdEnd>quint64(end)) return I::Invalid;
    qsizetype pos=cdOffset;
    quint64 expanded=0;
    for (quint16 n=0;n<count;++n) {
        if (timer.elapsed()>100) return I::Unsupported;
        if (quint64(pos)+46>cdEnd||u32(b,pos)!=0x02014b50) return I::Invalid;
        const quint16 flags=u16(b,pos+8), method=u16(b,pos+10);
        const quint32 expected=u32(b,pos+16), compressed=u32(b,pos+20), size=u32(b,pos+24);
        const quint16 nameSize=u16(b,pos+28), extra=u16(b,pos+30), comment=u16(b,pos+32);
        const quint32 local=u32(b,pos+42);
        const quint64 next=quint64(pos)+46+nameSize+extra+comment;
        if (next>cdEnd||quint64(local)+30>quint64(cdOffset)) return I::Invalid;
        if ((flags&0x41)||u16(b,pos+34)||size==0xffffffffU||compressed==0xffffffffU
            ||(method!=0&&method!=8)) return I::Unsupported;
        if (size>4*1024*1024||expanded+size>maxExpandedBytes) return I::Unsupported;
        expanded+=size;
        if (u32(b,local)!=0x04034b50||u16(b,local+8)!=method||u16(b,local+6)!=flags) return I::Invalid;
        const quint16 localName=u16(b,local+26), localExtra=u16(b,local+28);
        const quint64 start=quint64(local)+30+localName+localExtra;
        if (start+compressed>quint64(cdOffset)||localName!=nameSize
            ||b.mid(local+30,localName)!=b.mid(pos+46,nameSize)) return I::Invalid;
        if (!(flags&8) && (u32(b,local+14)!=expected||u32(b,local+18)!=compressed||u32(b,local+22)!=size))
            return I::Invalid;
        QByteArray decoded;
        if (method==0) {
            if (compressed!=size) return I::Invalid;
            decoded=b.mid(static_cast<qsizetype>(start),size);
        } else {
            decoded.resize(static_cast<qsizetype>(qMax<quint32>(size,1)));
            tinfl_decompressor state; tinfl_init(&state);
            size_t in=compressed,out=size;
            const auto status=tinfl_decompress(&state,
                reinterpret_cast<const mz_uint8*>(b.constData()+start),&in,
                reinterpret_cast<mz_uint8*>(decoded.data()),reinterpret_cast<mz_uint8*>(decoded.data()),&out,
                TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
            if (status!=TINFL_STATUS_DONE||in!=compressed||out!=size) return I::Invalid;
            decoded.resize(size);
        }
        if (crc(decoded)!=expected) return I::Invalid;
        pos=static_cast<qsizetype>(next);
    }
    return quint64(pos)==cdEnd ? I::Valid : I::Invalid;
}
}
