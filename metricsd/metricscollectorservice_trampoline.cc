#include "metricscollectorservice_trampoline.h"
#include "metricscollectorservice_impl.h"
#include "metrics_collector.h"

#include <thread>

namespace {
  MetricsCollector* metrics_collector_;
  std::thread* metricscollectorservice_thread;
}

MetricsCollectorServiceTrampoline::MetricsCollectorServiceTrampoline(
    void* metrics_collector) {
  metrics_collector_ = static_cast<MetricsCollector*>(metrics_collector);
}

void MetricsCollectorServiceTrampoline::Run() {
  // Start metricscollectorservice binder thread
  metricscollectorservice = new BnMetricsCollectorServiceImpl(this);
  metricscollectorservice_thread = new std::thread(
      &BnMetricsCollectorServiceImpl::Run, metricscollectorservice);
}

void MetricsCollectorServiceTrampoline::ProcessUserCrash() {
  metrics_collector_->ProcessUserCrash();
}
