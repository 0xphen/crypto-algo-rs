// use crate::preprocess::preprocess::PreprocessResult;
// use crate::utilities;

// pub struct MessageSchedule {
//     w: [String; 64],
// }

// impl MessageSchedule {
//     // The message schedule is a data structure that is composed of
//     // sixty-four 32-bit words. Hence, N is 64.
//     // pub fn new(preprocess_data: PreprocessResult) -> Self {
//     //     let N = preprocess_data.preprocessed_msg.len();
//     //     let mut schedule: Vec<String> = vec![];

//     //     for n in 0..N {
//     //         for t in 0..=63 {
//     //             schedule[t] = match t {
//     //                 // W0 - W15 is same as M0_n - M15_n
//     //                 0..=15 => preprocess_data.preprocessed_msg[n][t].clone(),
//     //                 16..=63 => {
//     //                     let mut ssig1 = MessageSchedule::ssig1(&schedule[t - 2]);

//     //                     let mut ssig0 = MessageSchedule::ssig0(&schedule[t - 15]);

//     //                     let w_1 = &schedule[t - 7];

//     //                     let w_2 = &schedule[t - 16];

//     //                     let mut w = utilities::binary_addition_modulo_2(&ssig1, &ssig0);
//     //                     w = utilities::binary_addition_mod_2_32(&w, &w_1);
//     //                     w = utilities::binary_addition_mod_2_32(&w, &w_2);
//     //                     w
//     //                 }
//     //                 _ => panic!("Unexpected value for t"),
//     //             };
//     //         }
//     //     }

//     //     todo!();
//     // }

//     pub fn ssig1(x: &str) -> String {
//         let rotr_17 = utilities::rotr(x, 17);
//         let rotr_19 = utilities::rotr(x, 19);
//         let shr_10 = utilities::shr(x, 10);

//         let mut result = utilities::binary_addition_modulo_2(&rotr_17, &rotr_19);

//         result = utilities::binary_addition_modulo_2(&result, &shr_10);

//         return result;
//     }

//     pub fn ssig0(x: &str) -> String {
//         let rotr_7 = utilities::rotr(x, 7);
//         let rotr_18 = utilities::rotr(x, 18);
//         let shr_3 = utilities::shr(x, 3);

//         let mut result = utilities::binary_addition_modulo_2(&rotr_7, &rotr_18);

//         result = utilities::binary_addition_modulo_2(&result, &shr_3);

//         return result;
//     }
// }

// pub mod hash_computation {}
