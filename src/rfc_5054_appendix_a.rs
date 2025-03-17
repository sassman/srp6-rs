use crate::prelude::*;

#[allow(non_snake_case)]
pub mod group_1024_bit {
    use super::*;

    /// 1024-bit group from [RFC5054 Appendix A](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
    /// The hexadecimal representation value for the prime
    pub fn N() -> PrimeModulus {
        PrimeModulus::from_hex_str_be(
            "EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
             9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
             8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
             7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
             FD5138FE 8376435B 9FC61D2F C0EB06E3",
        )
        .unwrap()
    }

    /// The generator for the 1024-bit group
    pub fn g() -> Generator {
        Generator::from(2)
    }
}

pub mod group_2048_bit {
    use super::*;

    pub fn N() -> PrimeModulus {
        PrimeModulus::from_hex_str_be(
            "AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
             3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
             CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
             D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
             7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
             436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
             5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
             03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
             94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
             9E4AFF73",
        )
        .unwrap()
    }

    pub fn g() -> Generator {
        Generator::from(2)
    }
}
