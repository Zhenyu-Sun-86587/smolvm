use crate::ipc::{Fault, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Policy {
    pub schema_version: u16,
    pub auto_standby: bool,
    pub standby_after_seconds: u32,
    pub auto_hibernate: bool,
    pub hibernate_after_seconds: u32,
    pub keep_running: bool,
    pub reclaim_priority: u8,
    pub pressure_reclaim: String,
    pub wake_conditions: WakeConditions,
    pub activity: ActivityPolicy,
    pub min_running_after_wake_seconds: u32,
    pub retry_backoff_seconds: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct WakeConditions {
    pub api_access:bool, pub service_access:bool, pub private_network_packet:bool, pub allow_cold_start:bool,
}
impl Default for WakeConditions {
    fn default()->Self {Self{api_access:true,service_access:true,private_network_packet:true,allow_cold_start:false}}
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct ActivityPolicy {
    pub protect_running_tasks:bool, pub protect_exec_sessions:bool, pub protect_inbound_connections:bool,
    pub protect_outbound_connections:bool, pub protect_running_leases:bool, pub unknown:String,
}
impl Default for ActivityPolicy {
    fn default()->Self {Self{protect_running_tasks:true,protect_exec_sessions:true,protect_inbound_connections:true,
                            protect_outbound_connections:true,protect_running_leases:true,unknown:"block_auto_sleep".into()}}
}
impl Default for Policy {
    fn default()->Self {Self{schema_version:1,auto_standby:true,standby_after_seconds:300,auto_hibernate:true,hibernate_after_seconds:1800,
                            keep_running:false,reclaim_priority:50,pressure_reclaim:"idle_only".into(),wake_conditions:Default::default(),
                            activity:Default::default(),min_running_after_wake_seconds:60,retry_backoff_seconds:60}}
}
impl Policy {
    pub fn validate(&self)->Result<()> {
        let max=365*24*3600;
        if self.schema_version!=1 || self.reclaim_priority>100 ||
            !matches!(self.pressure_reclaim.as_str(),"disabled"|"idle_only") || self.activity.unknown!="block_auto_sleep"
            || self.standby_after_seconds>max || self.hibernate_after_seconds>max
            || self.min_running_after_wake_seconds>max || self.retry_backoff_seconds==0 || self.retry_backoff_seconds>max
            || self.auto_standby && self.standby_after_seconds==0 || self.auto_hibernate && self.hibernate_after_seconds==0
            || self.auto_standby && self.auto_hibernate && self.hibernate_after_seconds<self.standby_after_seconds {
            return Err(Fault::invalid("invalid automatic lifecycle thresholds or protections"));
        }
        Ok(())
    }
    pub fn permits_wake(&self,trigger:&str)->bool {
        match trigger {"explicit"=>true,"api_access"=>self.wake_conditions.api_access,"service_access"=>self.wake_conditions.service_access,
            "private_network_packet"=>self.wake_conditions.private_network_packet,_=>false}
    }
    pub fn protects(&self,kind:&str)->bool {
        match kind {"task"=>self.activity.protect_running_tasks,"exec"=>self.activity.protect_exec_sessions,
                    "inbound"=>self.activity.protect_inbound_connections,"outbound"=>self.activity.protect_outbound_connections,
                    _=>true}
    }
}
