/*
 * Copyright © 2020-2021 Collabora, Ltd.
 * Author: Antonio Caggiano <antonio.caggiano@collabora.com>
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <pps/pps_driver.h>

#include "intel_pps_perf.h"

namespace pps
{
/// Timestamp correlation between CPU/GPU.
struct TimestampCorrelation {
   /// In CLOCK_MONOTONIC
   uint64_t cpu_timestamp;

   /// Engine timestamp associated with the OA unit
   uint64_t gpu_timestamp;
};

/// @brief Variable length sequence of bytes generated by Intel Obstervation Architecture (OA)
using PerfRecord = std::vector<uint8_t>;

/// @brief PPS Driver implementation for Intel graphics devices.
/// When sampling it may collect multiple perf-records at once. Each perf-record holds multiple
/// counter values. Those values are continuously incremented by the GPU. In order to get a delta,
/// the driver computes an _accumulation_ (`last_perf_record - previous_perf_record`).
/// For optimization purposes, it might ignore some perf-records, considering only those
/// perf-records close to the boundary of the sampling period range.
class IntelDriver : public Driver
{
   public:
   std::optional<TimestampCorrelation> query_correlation_timestamps() const;
   void get_new_correlation();

   /// @brief OA reports only have the lower 32 bits of the timestamp
   /// register, while correlation data has the whole 36 bits.
   /// @param gpu_ts a 32 bit OA report GPU timestamp
   /// @return The CPU timestamp relative to the argument
   uint64_t correlate_gpu_timestamp(uint32_t gpu_ts);

   uint64_t get_min_sampling_period_ns() override;
   bool init_perfcnt() override;
   void enable_counter(uint32_t counter_id) override;
   void enable_all_counters() override;
   void enable_perfcnt(uint64_t sampling_period_ns) override;
   void disable_perfcnt() override;
   bool dump_perfcnt() override;
   uint64_t next() override;

   /// @brief Requests the next perf sample
   /// @return The sample GPU timestamp
   uint32_t gpu_next();

   /// @brief Requests the next perf sample accumulating those which
   /// which duration is shorter than the requested sampling period
   /// @return The sample CPU timestamp
   uint64_t cpu_next();

   /// @param data Buffer of bytes to parse
   /// @param byte_count Number of bytes to parse
   /// @return A list of perf records parsed from raw data passed as input
   std::vector<PerfRecord> parse_perf_records(const std::vector<uint8_t> &data, size_t byte_count);

   /// @brief Reads data from the GPU metric set
   void read_data_from_metric_set();

   /// Sampling period in nanoseconds requested by the datasource
   uint64_t sampling_period_ns = 0;

   /// Keep track of the timestamp of the last sample generated
   uint64_t last_cpu_timestamp = 0;

   /// This is used to correlate CPU and GPU timestamps
   std::array<TimestampCorrelation, 64> correlations;

   /// Data buffer used to store data read from the metric set
   std::vector<uint8_t> metric_buffer = std::vector<uint8_t>(1024, 0);
   /// Number of bytes read so far still un-parsed.
   /// Reset once bytes from the metric buffer are parsed to perf records
   size_t total_bytes_read = 0;

   /// List of OA perf records read so far
   std::vector<PerfRecord> records;

   std::unique_ptr<IntelPerf> perf;

   // Accumulations are stored here
   struct intel_perf_query_result result = {};
};

} // namespace pps
