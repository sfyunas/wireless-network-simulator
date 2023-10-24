// IMPORTANT: If the Software includes one or more computer programs bearing a Keysight copyright notice and in
// source code format (“Source Files”), such Source Files are subject to the terms and conditions of the Keysight
// Software End-User License Agreement (“EULA”) www.Keysight.com/find/sweula and these Supplemental Terms.
// BY USING THE SOURCE FILES, YOU AGREE TO BE BOUND BY THE TERMS AND CONDITIONS OF THE EULA INCLUDING THESE
// SUPPLEMENTAL TERMS.IF YOU DO NOT AGREE TO THESE TERMS AND CONDITIONS, DO NOT USE THE SOFTWARE.
//
//	1.	Additional Rights and Limitations. If Source Files are included with the Software, Keysight grants you
//		a limited, non-exclusive license, without a right to sub-license, to use the Source Files solely for its
//		intended function as part of the Software. You are not permitted to, and shall not, incorporate or use
//	    any portion of the Source Files or the algorithms and ideas therein in connection with any other software.
//		You own any such modifications and Keysight retains all right, title and interest in the underlying
//		Software and Source Files. All rights not expressly granted are reserved by Keysight.
//
//	2.	Distribution Restriction. You will not distribute the Source Files, unmodified or modified, or any
//		Derivative File to an external party without Keysight’s prior written authorization and will be pursuant
//		to an enforceable agreement that provides similar protections for Keysight and its suppliers as those
//		contained in the EULA and these Supplemental Terms. “Derivative File” means any program, library or file
//		that comprises or contains any portion of, or is in whole or in part based upon, or is a derivative work
//		of, the Software or any executable code and/or Source Files supplied by Keysight, including, but not
//		limited to, the simulation kernel, model libraries, or model files, or containing portions of Source
//		Files therefrom.
//
//	3.	General. Capitalized terms used in these Supplemental Terms and not otherwise defined herein shall have
//		the meanings assigned to them in the EULA. To the extent that any of these Supplemental Terms conflict
//		with terms in the EULA, these Supplemental Terms control solely with respect to the Source Files.

/// \defgroup Package_PARTITION PARTITION

/// \file
/// \ingroup Package_PARTITION
/// This file contains declarations of some functions for partition threads.

#ifndef PARTITION_H
#define PARTITION_H

#include <stdio.h>
#include <fstream>

#include "clock.h"
#include "coordinates.h"
#include "main.h"
#include "mapping.h"
#include "message.h"
#include "terrain.h"
#include "mobility.h"
#include "motion.hpp"
#include "splaytree.h"
#include "weather.h"
#include "dynamic.h"
#include <map>
#include <vector>
#include <list>
#include <string>
#include <unordered_map>
#include "external.h"
#include "simplesplay.h"
#include "sched_std_library.h"
#include "prop_mimo.h"
#include "prop_heatmap.h"
#include "attachment.h"
#include <functional>
#include <boost/container/flat_set.hpp>

#include "prop_flat_binning.h"
#include "UrbanCache.h"
#include "product_info.h"

#include "dynamic_entity_creation.h"

#include "cpu_affinity.h"

#ifdef PARALLEL //Parallel
#include "parallel.h"
#endif //endParallel
#include "spectrum.h"

#ifdef ELEKTRAFIED
#include "elektra.hpp"

class SopsPropertyManager;
#endif

class PropPDPData;

#ifdef NDT_INTERFACE
class CyberState;
#endif // NDT_INTERFACE

#ifdef _HOSTMODEL_EXATA

namespace HostModel {
class Profile;
class UserProfile;
class VulnerabilityDB;
class Process;
class UsageInfo;
class ActionStore;
class EmailTemplateInfo;
using SideDatabase = std::map<NodeId, std::string>;
using ServiceDatabase = std::multimap<NodeId, std::string>;
using SharedFileDatabase = std::vector<NodeId>;
using EmailTemplateDatabase = std::map<std::string, EmailTemplateInfo>;
} //namespace HostModel

#endif // _HOSTMODEL_EXATA

namespace Proc
{
    namespace DB
    {
        class StatsDBController;
    }
}

/// The number of percentage complete statements to print
#define NUM_SIM_TIME_STATUS_PRINTS 100

/// A default unitialized communication ID.
#define COMMUNICATION_ID_INVALID  0

/// A value to indicate real time interpartition communication
#define COMMUNICATION_DELAY_REAL_TIME -1

///
/*union MessageListCell {
    Message messageCell;
    union MessageListCell* next;
};*/

///
union MessagePayloadListCell {
    char payloadMemory[MAX_CACHED_PAYLOAD_SIZE];
    union MessagePayloadListCell* next;
};

///
union MessageInfoListCell {
    char infoMemory[SMALL_INFO_SPACE_SIZE];
    union MessageInfoListCell* next;
};

///
union SplayNodeListCell {
    SplayNode splayNodeCell;
    union SplayNodeListCell* next;
};


typedef Int64 EventCounter;

typedef int CommunicatorId;
typedef void (*PartitionCommunicationHandler) (PartitionData *, Message *);

typedef std::map <std::string, int >             PartitionCommunicatorMap;
typedef std::map <std::string, int >::iterator   PartitionCommunicatorMapIter;

typedef std::vector <Node *>                     NodePointerCollection;
typedef std::vector <Node *>::iterator           NodePointerCollectionIter;

typedef std::map <std::string, void *>           ClientStateDictionary;
typedef std::map <std::string, void *>::iterator ClientStateDictionaryIter;

// SendMT
class QNThreadMutex;

// SendMT
class QNThreadMutex;
extern clocktype PrintSimTimeInterval;

class StatsDb;

class MessageSendRemoteInfo;

class IntervalStats;

struct MessageLinkStats
{
    long long messageCount = 0;
    clocktype minimumDelay = CLOCKTYPE_MAX;
};

#include <memory> // std::allocator

//PARALLEL satcom stuff...
/// Data structure containing interfaceIndex and
/// Node* for a node in a single subnet
struct SubnetMemberData
{
    Node*   node;
    NodeId  nodeId;
    int     interfaceIndex;
    Address address;
    int     partitionIndex;
};


/// Data structure containing member data info
/// for all nodes in a single subnet
struct PartitionSubnetList
{
    SubnetMemberData *memberList = nullptr;
    int numMembers = 0;

    void setAddressString(const string &address) { m_addressString = address; }
    string getAddressString() const { return m_addressString; }
private:
    std::string m_addressString;
};


/// Data structure containing subnet member data
/// for all subnets
struct PartitionSubnetData
{
    PartitionSubnetList* subnetList;
    int numSubnets;
};

struct PartitionPathLossSample
{
    clocktype sampleTime;
    int nodeId1;
    int nodeId2;
    double* pathloss;
};

// Forward declaration
class STAT_StatisticsList;
class PHY_CONN_NodePositionData;
class RecordReplayInterface;

/// \class HITLInfo
/// \brief  Handles the info for one HITL command.
/// \Info includes the node ID, the instance ID of the app, and the victim node ID.
class HITLInfo
{
public:
    NodeAddress nodeId;

    NodeAddress victimNodeId;

    HITLInfo(NodeAddress nodeId,
             NodeAddress victimNodeId) : nodeId(nodeId),
                                         victimNodeId(victimNodeId)
    {}

    HITLInfo(NodeAddress nodeId) : nodeId(nodeId),
                                  victimNodeId(0)
    {}

};

/// \class HITLApplication
/// \brief handle application type and info
class HITLApplication
{
public:
    /// application type
    AppType appType;

    /// HITLInfo vector
    std::vector<HITLInfo> apps;
};

/// Contains global information for this partition.
class PartitionData : public AttachmentPoint {
private:
    clocktype   m_theCurrentTime;
    int m_numPartitions;
    int m_numThreadsPerPartition;

public:
    PartitionData(int thePartitionId, int numPartitions, int numOPHosts = 0
#ifdef NDT_INTERFACE
                    , int numGUIs = 0
#endif // NDT_INTERFACE
                 );

    clocktype m_baseTime;        // timevalue when simulation appears to have started at.
    const SimulationProperties *simProps;
    int partitionId;        // Identifier for this partition
    D_Int32 numNodes;       // Number of nodes in the entire simulation.
    int seedVal;

    NodePositions *nodePositions;

    TerrainData* terrainData;

    AddressMapType *addressMapPtr;
    IdToNodePtrMap  nodeIdHash[32];

    clocktype   safeTime;
    clocktype   nextInternalEvent;
    clocktype   externalInterfaceHorizon;
    D_Clocktype theCurrentTimeDynamic; // dynamic copy of theCurrentTime
    D_Clocktype maxSimClock;
    double      startRealTime;
    clocktype    mimoUpdateInterval;  // how often to recalculate the random part of the mimo propagation
    const MIMO_TGn_cluster* mimo_Model;  // which tgn model to use

    Node* getNodeByNetworkAddress(NodeAddress targetAddr);
    bool guiOption;

    NodeInput* nodeInput;
    Node**     nodeData;      /* Information about all nodes */
    std::vector<Node*> nodeVector;

    int          numChannels;
    int          numFixedChannels;
    PropChannel* propChannel;

    struct CompareByNodeId {
        bool operator()(const Node& n1, const Node& n2) const { return n1.nodeId < n2.nodeId; }
    };
    using PropagationNodeSet = boost::container::flat_set<std::reference_wrapper<Node>, CompareByNodeId>;
    std::vector<PropagationNodeSet> m_listenableNodes;  // indexed by channel number

    using PropagationPartitionSet = boost::container::flat_set<int>;
    std::vector<PropagationPartitionSet> m_listenablePartitions;  // indexed by channel number

    // Pathloss Matrix value
    // moved from PropProfile to here as PropProfile is shared by all partitions
    // This is an array with length equal to numChannels;
    std::map <std::pair<NodeId, NodeId>, double>** pathLossMatrix;
    int plCurrentIndex;
    clocktype plNextLoadTime;

    int          numProfiles;

    // pathloss Propagation Delay Phase (PDP)
    PropPDPData** m_pdp = nullptr;
    
    /*
     * This is a pointer to a node in this partition. A node keeps pointers
     * to other nodes in the same partition.
     * If this partitcular node moves out of this partition, this variable
     * will also have to be updated.
     */
    Node       *firstNode;
    // In MPI only, this is a list of remote nodes. Remote nodes
    // are "shadow" nodes and have a very small subset of capabilities.
    // Note, in shared memory all nodes will remain in the normal list.
    Node        *firstRemoteNode;
    // This container holds references to all nodes, in order, for
    // both local and remote nodes.
    NodePointerCollection * allNodes;

    // new motion model
    std::vector<MotionDescriptor *> motionDescriptors; // indexed by Node::nodeIndex, to save space

    int                     msgFreeListNum;
    Message                *msgFreeList;
    int                     msgPayloadFreeListNum;
    MessagePayloadListCell *msgPayloadFreeList;
    int                     msgInfoFreeListNum;
    MessageInfoListCell    *msgInfoFreeList;
    int                     splayNodeFreeListNum;
    SplayNodeListCell      *splayNodeFreeList;

    /*
     * When SCHEDULER is SPLAYTREE
     * Each node keeps a splay tree of all its future messages.
     * The partition keeps a heap of all the nodes in the partition,
     * so that we can easily retrieve the earliest message in this
     * particular partition.
     */
    HeapSplayTree heapSplayTree;
    /*
     * When SCHEDULER is STDLIB
     */
    StlHeap *    heapStdlib;

    MobilityHeap mobilityHeap;
    StlHeap *       looseEvsHeap;

    // Generic event queue, for events not assigned to a particular node
    SimpleSplayTree genericEventTree;

    // these need to be processed last after all other partition and node events
    // ex: statsDB timer events,
    SimpleSplayTree processLastEventTree;

    EventCounter numberOfEvents;
    EventCounter numberOfMobilityEvents;

    /*
     * Weather related variables.
     */
    WeatherPattern** weatherPatterns;
    int              numberOfWeatherPatterns;
    int              weatherMobilitySequenceNumber;
    clocktype        weatherMovementInterval;

    FILE    *statFd;       /* file descriptor used for statistics */

    BOOL    traceEnabled;
    FILE    *traceFd;      /* file descriptor used for packet tracing */

    Node    *activeNode;

    BOOL realTimeLogEnabled;
    FILE *realTimeFd;   /* file descriptor for real time log */
    EXTERNAL_InterfaceList interfaceList;
    D_Hierarchy dynamicHierarchy;
    STAT_StatisticsList* stats;
    std::shared_ptr<Elektra::M1>* m_statAggregationUpdateMsgs;
    std::shared_ptr<Elektra::M1>* m_statSummaryUpdateMsgs;

    EXTERNAL_Interface *    interfaceTable [EXTERNAL_TYPE_MAX];
    CommunicatorId          externalForwardCommunicator;
    CommunicatorId          externalSimulationDurationCommunicator;

    SchedulerInfo   *schedulerInfo;     // Pointer to the info struct for the schedular
    // to be used with this partition

    int                   numAntennaModels;
    AntennaModelGlobal    *antennaModels;  // Global Model list for partition
    int                   numAntennaPatterns;
    AntennaPattern        *antennaPatterns;//Global pattern list for partition

    WallClock *           wallClock;

    // Distribution Stuff
    UserProfileDataMapping *userProfileDataMapping;
    TrafficPatternDataMapping *trafficPatternMapping;

    // RegisteredCommunicators
    // Map of registered communicator names and their corresponding array indexes
    // std::map <const char *, int, CharComparitor>         communicators;
    PartitionCommunicatorMap *          communicators;
    PartitionCommunicationHandler *     handlerArray;
    int                                 nextAvailableCommunicator;
    int                                 communicatorArraySize;
    // mutex       communicatorsLock;
    bool                                communicatorsFrozen;

    // Dictionary of Client state
    ClientStateDictionary *             clientState;

    bool                  isRealTime;

    // Subnet list array
    PartitionSubnetData subnetData; // Remember "SUBNET ..." configuration
    PartitionSubnetData linkData;   // Remember "LINK ....." configuration

    BOOL isCreateConnectFile;
    clocktype connectSampleTimeInterval;
    char connectFilename[MAX_STRING_LENGTH];

    int **ConnectionTable;
    int *NodeMappingArray;
    int ***ConnectionTablePerChannel;
    int ***ConnectionTablePerPhyIndex;

    PHY_CONN_NodePositionData* nodePositionData;

    //Address of forwarding node for cross-partition forward messages
    NodeAddress EXTERNAL_lastIdToInvokeForward;

    // Whether interface to AGI STK is enabled.
    BOOL isAgiInterfaceEnabled;

    BOOL isEmulationMode;
    BOOL isRtIndicator;
    int masterPartitionForCluster;
    int clusterId;
    BOOL partitionOnSameCluster[32];
    clocktype delayExt;
    double dropProbExt;
    std::map<int, int> *virtualLanGateways;
    RecordReplayInterface *rrInterface;

    // The UrbanCache may be created by the urban terrain processing to retain
    // the path data for stationary objects. It is set byt the specific urban
    // terrain processing. It is kept in the partition for thread safety.
    UrbanCache* urbanCache;

    // METHODS
    int getNumPartitions() { return m_numPartitions; }
    void setNumPartitions(int numPartitions) { m_numPartitions = numPartitions; }

    // Return TRUE if the simulation is running in parallel
    BOOL isRunningInParallel() { return m_numPartitions * m_numThreadsPerPartition > 1; }

    /// Returns the simulation time at a global level
    /// For the current time of a node, use Node::getNodeTime().
    /// PartitionData::getGlobalTime() should only be used for
    /// timing at the partition or global level.
    ///
    /// \return The current global simulation time
    clocktype getGlobalTime() const { return m_theCurrentTime; }

    /// \copydoc PartitionData::getGlobalTime()
    Qualnet::SimClock::time_point getGlobalTimePoint() const {
        return to_time_point(getGlobalTime());
    }

    void setTime(clocktype t) { m_theCurrentTime = t; }
    template <typename Rep, typename Ratio>
    void setTimePoint(const std::chrono::time_point<Qualnet::SimClock, std::chrono::duration<Rep, Ratio>>& t) {
        setTime(to_clocktype(t));
    }

    // new mobility methods
    void SetNodeMotionCalculators();
    void LoadFileBasedMotionData();
    bool ParametrizeMotionData(Node *nodePtr,
                               coordinate_system_type coordSystemType,
                               clocktype newTime,
                               const Coordinates *coordValues,
                               const Orientation *angleValues);
    bool GetNodeMotion(const Node *nodePtr,
                       coordinate_system_type coordSystemType,
                       clocktype currentTime,
                       Coordinates *coordValues,
                       Coordinates *velocityValues,
                       Orientation *angleValues);

    inline bool GetNodeMotionById(NodeAddress nodeId,
                                  coordinate_system_type coordSystemType,
                                  clocktype currentTime,
                                  Coordinates *coordValues,
                                  Coordinates *velocityValues,
                                  Orientation *angleValues)
    {
        return GetNodeMotion(MAPPING_GetNodePtrFromHash(nodeIdHash, nodeId),
                             coordSystemType,
                             currentTime,
                             coordValues,
                             velocityValues,
                             angleValues);
    }

    PARALLEL_PropDelay_NodePositionData *dynamicPropDelayNodePositionData;

    // SendMT
    QNThreadMutex*         sendMTListMutex;
    std::list <Message*>*  sendMTList;
    Proc::DB::StatsDBController* dbController;

    spectrum theSpectrum;

#ifdef ELEKTRAFIED
    std::shared_ptr<PartitionManager> m_rfm;
    std::shared_ptr<PartitionManager>& rfm() { return m_rfm; }
    std::shared_ptr<PartitionEndpoint> m_efm;
    std::shared_ptr<PartitionEndpoint>& efm() { return m_efm; }
#ifdef SOPSVOPS_INTERFACE
    SopsPropertyManager* m_spm;
    SopsPropertyManager* spm() {return m_spm; }
#endif
#endif

#ifdef PARALLEL //Parallel
    // list of "shadow" node pointers for other partitions
    IdToNodePtrMap        remoteNodeIdHash[32];
    LookaheadCalculator*  lookaheadCalculator;
    clocktype             reportedEOT;
    bool                  looseSynchronization;

    // MAPPING relate partition communicator IDs.
    CommunicatorId          mappingAddrChgCmtr;
#endif // PARALLEL

#ifdef ADDON_DB
    // STATS DB CODE
    StatsDb* statsDb;
#endif

#ifdef CYBER_LIB
    std::map<std::string, HITLApplication> hitlApplicationMap;
#endif // CYBER_LIB

    int nolNumVirtualNodes = 0;

    /// Map to store heatmap grid points co-ordinates with grid level as key
    /// nullptr if heat map model is not enabled
    /// will initialized by the partition node on which heat map is enabled
    HeatMapGrid* heatMapGrid;

    // data structure to store the heatmap locations
    std::vector<HeatMapPointData*>* heatMapLocations;

    // number of heatmap worker threads
    int heatMapThreads;

    // heatmap output file
    std::fstream heatMapFile;

    IntervalStats* horizonWaitStats = nullptr;
    IntervalStats* barrierWaitStats = nullptr;
    IntervalStats* testWaitStats = nullptr;

    // Prop overlapping signal list for caching
    std::list<PropOverlappingSignal*> overlappingSignalList;
    // Users should not modify anything above this line.
#ifdef UNDERWATER_LIB
    ElevationTerrainData* m_bathymetricData;
    float m_underwaterDefaultMaxDepth;
#endif // UNDERWATER_LIB
    DynamicEntityCreation dynamicEntityCreation;
#ifdef CYBER_LIB
#ifdef _HOSTMODEL_EXATA
    void* dbDriver;
#endif // _HOSTMODEL_EXATA
#ifdef NDT_INTERFACE
    CyberState* partitionCyberState;
#endif // NDT_INTERFACE
#endif // CYBER_LIB
#ifdef ELEKTRAFIED
    std::map<std::string, std::string> spsrPropertyBufferMap;
#endif // ELEKTRAFIED
    unordered_set<UInt32>* allSwitchNodeIds;
#ifdef _HOSTMODEL_EXATA
    bool hostModelEnabled;
    /// HostProfileDatabase
    std::map<std::string, std::shared_ptr<HostModel::Profile>> hostProfileDatabase;
    /// VulnerabilityStorePtr
    std::shared_ptr<HostModel::VulnerabilityDB> vulnerabilityStoreDatabase;
    /// ActionStorePtr
    std::shared_ptr<HostModel::ActionStore> actionStoreDatabase;
    /// UsageInfoStore
    std::map<std::string, std::shared_ptr<HostModel::UsageInfo>> usageInfoStore;
    /// ProcessStore
    std::map<std::string, std::shared_ptr<HostModel::Process>> processInfoStore;
    /// UserProfileDatabase
    std::map<std::string, std::shared_ptr<HostModel::UserProfile>> userProfileDatabase;
#ifndef NDT_INTERFACE
    HostModel::SideDatabase sideDatabase;
    HostModel::ServiceDatabase serviceDatabase;
    HostModel::SharedFileDatabase sharedFileDatabase;
#endif // NDT_INTERFACE
    HostModel::EmailTemplateDatabase emailTemplateDatabase;
#endif // _HOSTMODEL_EXATA

    cpu_set ipneCpuset;

    Elektra::Port statsAggregateOutputPorts;
    Elektra::Port statsSummaryOutputPorts;
};

/// Global properties of the simulation for all partitions.
class SimulationProperties;

/// Inline function used to get terrainData pointer.
///
/// \param partitionData  pointer to partitionData
inline
TerrainData* PARTITION_GetTerrainPtr(PartitionData* partitionData)
{
    return partitionData->terrainData;
}

/// Function used to allocate and perform inititlaization of
/// of an empty partition data structure.
///
/// \param partitionId  the partition ID, used for parallel
/// \param numPartitions  for parallel
/// \param numOPHosts  number of Operational Hosts that are licensed to be mapped
/// \param numGUIs  number of EXata GUIs that can be connected to the multi-gui interface
PartitionData* PARTITION_CreateEmptyPartition(
    int             partitionId,
    int             numPartitions,
    int             numOPHosts = 0
//#ifdef NDT_INTERFACE
//    , int             numGUIs = 0
//#endif // NDT_INTERFACE
);

/// Function used to initialize a partition.
///
/// \param partitionData  an empty partition data structure
/// \param terrainData  dimensions, terrain database, etc.
/// \param maxSimClock  length of the scenario
/// \param startRealTime  for synchronizing with the realtime
/// \param numNodes  number of nodes in the simulation
/// \param traceEnabled  is packet tracing enabled?
/// \param addressMapPtr  contains Node ID <--> IP address mappings
/// \param nodePositions  initial node locations and partition assignments
/// \param nodeInput  contains all the input parameters
/// \param seedVal  the global random seed
/// \param nodePlacementTypeCounts  gives information about node placemt
/// \param experimentPrefix  the experiment name
/// \param startSimClock  the simulation starting time
void PARTITION_InitializePartition(PartitionData * partitionData,
    TerrainData*    terrainData,
    const SimulationProperties& simProps,
    double          startRealTime,
    int             numNodes,
    BOOL            traceEnabled,
    AddressMapType* addressMapPtr,
    NodePositions*  nodePositions,
    NodeInput*      nodeInput,
    int             seedVal,
    int*            nodePlacementTypeCounts,
    char*           experimentPrefix);

/// Function used to allocate and initialize the nodes on a
/// partition.
///
/// \param partitionData  an pre-initialized partition data structure
void PARTITION_InitializeNodes(PartitionData* partitionData);


/// Finalizes the nodes on the partition.
///
/// \param partitionData  an pre-initialized partition data structure
void PARTITION_Finalize(PartitionData* partitionData);


/// Creates and initializes the nodes, then processes
/// events on this partition.
///
/// \param partitionData  an pre-initialized partition data structure

void* PARTITION_ProcessPartition(PartitionData* partitionData);

/// Messages sent by worker threads outside of the main
/// simulation event loop MUST call MESSAGE_SendMT ().
/// This funciton then is the other half - where the multi-thread
/// messages are properly added to the event list.
///
/// \param partitionData  an pre-initialized partition data structure
void PARTITION_ProcessSendMT (PartitionData * partitionData);

/// Returns a pointer to the node or NULL if the node is not
/// on this partition.  If remoteOK is TRUE, returns a pointer
/// to this partition's proxy for a remote node if the node
/// does not belong to this partition.  This feature should
/// be used with great care, as the proxy is incomplete.
/// Returns TRUE if the node was successfully found.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param node  for returning the node pointer
/// \param nodeId  the node's ID
/// \param remoteOK  is it ok to return a pointer to proxy node?
///
/// \return returns TRUE if the node was succesfully found
bool PARTITION_ReturnNodePointer(PartitionData* partitionData,
                                 Node**         node,
                                 NodeId         nodeId,
                                 BOOL           remoteOK = FALSE);


/// Determines whether the node ID exists in the scenario.
/// Must follow node creation.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param nodeId  the node's ID
BOOL PARTITION_NodeExists(PartitionData* partitionData,
                          NodeId         nodeId);


/// If dynamic statistics reporting is enabled,
/// generates statistics for enabled layers.
///
/// \param partitionData  an pre-initialized partition data structure
void PARTITION_PrintRunTimeStats(PartitionData* partitionData);

/// Schedules a generic partition-level event.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param msg  an event
/// \param eventTime  the time the event should occur
/// \param scheduleBeforeNodes  process event before or after node events
///
/// \note The \c msg->relayNodeId and \c msg->relaySequenceNum fields should
///   be set before calling this function, if there's any possibility of two
///   partition events of the same type being scheduled at the same time, and
///   the order of the events matters.
void PARTITION_SchedulePartitionEvent(PartitionData* partitionData,
                                      Message*       msg,
                                      clocktype      eventTime,
                                      bool  scheduleBeforeNodes = true);

/// An empty function for protocols to use that need to
/// schedule and handle partition-level events.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param msg  an event
void PARTITION_HandlePartitionEvent(PartitionData* partitionData,
                                    Message*       msg);

/// Sets or replaces a pointer to client-state, identifed by name,
/// in the indicated partition.
/// Allows client code, like external iterfaces, to store
/// their own data in the partition. The client's state pointer
/// is set and found by name. If the caller passes a name for
/// client state that is already being stored, the state pointer
/// replaces what was already there.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param stateName  Name used to locate this client state
///    information
/// \param clientState  Pointer to whatever data-structure the
///    client wishes to store.
void PARTITION_ClientStateSet(PartitionData* partitionData,
                              const char*    stateName,
                              void*          clientState);

/// Looks up the requested client-state by name. Returns NULL
/// if the state isn't present.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param stateName  Name used to locate this client state
///    information
///
/// \return returns the client state
void* PARTITION_ClientStateFind(PartitionData* partitionData,
                                const char*    stateName);

/// Allocates a message id and registers the handler
/// that will be invoked to receive callbacks
/// when messages are with the id are sent.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param name  Your name for this type of message.
///    Must be unique in the simulation.
/// \param handler  Function
///    to call for processing this type of message.
///
/// \return used to later when calling MESSAGE_Alloc().
CommunicatorId PARTITION_COMMUNICATION_RegisterCommunicator (
    PartitionData*                partitionData,
    const char*                   name,
    PartitionCommunicationHandler handler);

/// Locate an already registered commincator.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param name          : std:  Your name for this type of message.
///
/// \return found communicator Id or COMMUNICATION_ID_INVALID
/// if not found.
CommunicatorId PARTITION_COMMUNICATION_FindCommunicator (
    PartitionData* partitionData,
    std::string    name);


/// Transmit a message to a partition.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param partitionId  partition to send the message to
/// \param msg  Message to send. You are required to follow
///    several rules in regard to the message's contents.
///    The contents must not contain pointers. The message
///    should no longer be modified or freed after calling this
///    function.
/// \param delay  When the message should execute. Special delay
///    value of COMMUNICATION_DELAY_REAL_TIME which means that
///    the receiving partition will process the message
///    as soon as possible. Note, that if you want repetable
///    and consistent simulation results you can only use this delay
///    value for processing that won't affect simulation event
///    ordering. e.g. your msg is to trigger a call to an external
///    program.
void PARTITION_COMMUNICATION_SendToPartition(
    PartitionData* partitionData,
    int            partitionId,
    Message*       msg,
    clocktype      delay);

/// Transmit a message to all partitions.
///
/// \param partitionData  an pre-initialized partition data structure
/// \param msg  Message to send. You are required to follow
///    several rules in regard to the message's contents.
///    The contents must not contain pointers. The message
///    should no longer be modified or freed after calling this
///    function.
/// \param delay  When the message should execute. Special delay
///    value of COMMUNICATION_DELAY_REAL_TIME which means that
///    the receiving partition will process the message
///    as soon as possible. Note, that if you want repetable
///    and consistent simulation results you can only use this delay
///    value for processing that won't affect simulation event
///    ordering. e.g. your msg is to trigger a call to an external
///    program.
void PARTITION_COMMUNICATION_SendToAllPartitions(
    PartitionData* partitionData,
    Message*       msg,
    clocktype      delay);
/*
 * FUNCTION     PARTITION_GetRealTimeMode ()
 * PURPOSE      Returns true if the simulation should execute
 *              keeping up, but not faster than,
 *              real time. e.g. IPNE or HLA time managed.
 *
 * Parameters
 *      partitionData: a pre-initialized partition data structure
 *
 */
bool
PARTITION_GetRealTimeMode (PartitionData * partitionData);

/*
 * function     PARTITION_SetRealTimeMode ()
 * purpose      Simulation should execute keeping up, but not faster than,
 *              real time. Examples are IPNE or HLA time managed.
 *
 * parameters
 *      partitionData: a pre-initialized partition data structure
 *      runAsRealtime: true to indicate real time execution
 */
void
PARTITION_SetRealTimeMode (PartitionData * partition, bool runAsRealtime);

/*
 * FUNCTION     UpdateNextInternalEventTime
 * PURPOSE      Calculates the time of the next internal event and puts it in
 *              partitionData->nextInternalEvent;
 */
void UpdateNextInternalEventTime(PartitionData* partitionData);

/*
 * FUNCTION     PARTITION_GlobalInit
 * PURPOSE      Initializes process variables before partitions are
 *              created
 */
void PARTITION_GlobalInit(NodeInput* nodeInput,
                          int numberOfProcessors,
                          char* experimentPrefix);

// The following functions may belong in non-partition header and cfile
// And are used in the licencing
/// This will return in a string the current directory
/// qualnet is executing from
///
///
/// \return string containing current qualnet directory
std::string IO_ReturnBaseDirectory();


/// This will return a boolean true if file exists, and false if not
///
///
/// \return boolean true/false if file exists
BOOL IO_SourceFileExists(std::string fileToTest);


/// This will return in a string the formatted
/// yes/no line for whether the fingerprint file exists for given
/// library
///
///
/// \return string containing list of libraries
std::string IO_CheckSourceLibrary(std::string filePath);


/// This will return in a string a list of libraries
/// currently compiled into product as well as those which
/// have source code available.
///
///    std::string licensePath : path of licence file including file itself
///    BOOL onlyForGUI : Print additional info for GUI.
///    BOOL validTS : A valid license exists in Trusted Storage or not
///    int *expirationDates : NULL it means that we just want to get
///                           the type of license.
///
/// \return string containing list of libraries
std::string IO_ReturnSourceAndCompiledLibraries(std::string licensePath,
                                                BOOL onlyForGUI,
                                                BOOL validTS = TRUE,
                                                int *expirationDates = NULL);

/// This will return in a string the status message for the library
///
///    std::string library: library to be tested for
///    std::string licensePath: path of licene file including file itself
///    BOOL validTS : A valid license may exist in Trusted Storage if true
///    int *expirationDates : If NULL it means that we just want to get
///                           the type of license.
///
/// \return string containing the status message for the library
std::string IO_ReturnLibraryStatus(std::string library,
                                    std::string licensePath,
                                    BOOL validTS = TRUE,
                                    int *expirationDates = NULL);

/// This will return true if it is a node-locked license.
///
///    std::string licensePath : path of licence file including file itself
///
/// \return true if it is a node-locked license
bool IO_IsNodeLocked(std::string licensePath);

/// This will return in a string a list of libraries
/// currently compiled into product as well as those which
/// have source code available.
///
///    std::string featureName: name of feature to look for
///
/// \return string containing expiration date for this feature
std::string IO_ReturnExpirationDateFromLicenseFeature(vector<std::string> *licenseLines, std::string featureName);

/// This will return in a string the expiration date of the library
///
///    :: BOOL onlyForGUI - additional information printed for gui
///
/// \return string containing expiration date for this feature
std::string IO_ReturnExpirationDateFromNumericalDate(int numericalExpiration,BOOL onlyForGUI);

/// This will return in a string the expiration date of the library
///
///    :: BOOL onlyForGUI - additional information printed for gui
///
/// \return string containing expiration date for this feature
std::string IO_ReturnExpirationDateFromNumericalDate(int numericalExpiration,BOOL onlyForGUI);

/// Parse a FlexLM date in a platform safe way
///
///
/// \return UInt64 containing the date
UInt64 IO_ParseFlexLMDate(const char* date);

// Parse a Version date in a platform safe way
//
// :: const char * date: date obtain from VERSION.TXT
// :: char * verDate: pointer to char array to store version date
//
void IO_ParseVersionDate(char*,const char* date);

/// This will return in a string the status message for the library
/// used with the -print_libraries option
///
/// \param expDate: Date when the license for this
///                 library expires
/// \param binaryStatus: true/false if library compiled in
/// \param fileName: Additional file to be checked for
///                  existence in order for the status to be ok
/// \return string containing status message for library
std::string IO_ReturnStatusMessageFromLibraryInfo(std::string expDate, BOOL binaryStatus, std::string fileName);

/// This will return in a string the library name from its index
//           :: because flexlm won't allow std strucsts in main.cpp
//           :: but main.cpp is the only place flex structs are allowed
///
///
/// \return string containing library name
std::string IO_ReturnLibraryNameFromAbsoluteIndex(int index);

#ifdef GPROF
#if !defined(USE_MPI)
#include <sys/time.h>
extern struct itimerval g_itimer;
#endif
#endif

/* FUNCTION     PARTITION_SetSimulationEndTime
 * PURPOSE      To end the simulation in middle of execution
 *                Typically called by external interfaces, or upon
 *                external interrupts.
 *
 * Parameters
 *    partitionData: ParitionData *: pointer to partitionData
 *    duration : clocktype : interval after which the simulation must end
 */
void PARTITION_SetSimulationEndTime(
    PartitionData *partitionData,
    clocktype duration);

/*
 * API :: PARTITION_RequestEndSimulation
 * PURPOSE:: Request the simulation to end now
 */
void PARTITION_RequestEndSimulation();


/* FUNCTION     PARTITION_PrintUsage
 * PURPOSE      Prints the command-line usage of the application.
 *
 * Parameters
 *    commandName: const char*: The command name of the application.
 */
void PARTITION_PrintUsage( const char* commandName, ProductType productType);


/// Structure storing configuration from command line
struct CommandLineConfig {
    bool isEmulationMode = false;
    int seedVal = 0;
    BOOL seedValSet = FALSE;
    BOOL dbRegression = FALSE;
    int numberOfPartitions = 0;
    int numberOfThreadsPerPartition = 1;
    std::string experimentName;
    char experimentPrefix[MAX_STRING_LENGTH];
    char statFileName[MAX_STRING_LENGTH];
    char traceFileName[MAX_STRING_LENGTH];
    bool sopsvopsInterface = false;
    int sopsPort = 0;
    SopsProtocol sopsProtocol = SOPS_PROTOCOL_default;
    std::string clusterConfigFilename;
    int machineNum = 1;
    std::unordered_map<std::string, std::string> licenseLibrariesStatus;
    bool samplePathlossMode = false;
    NodeId sampleTxNodeId = 1;
    char txLocationsFile[MAX_STRING_LENGTH];
    char rxLocationsFile[MAX_STRING_LENGTH];
    int pathlossThreads = 4;
    bool radioRangeMode = false;
    NodeId radioRangeTxNodeId = 1;
    NodeId radioRangeRxNodeId = 2;
    clocktype maxClock = 0;
    bool auto_np = false;
    int coreCount = 0;

    CommandLineConfig() {
        memset(statFileName, 0, MAX_STRING_LENGTH);
        memset(experimentPrefix, 0, MAX_STRING_LENGTH);
        memset(traceFileName, 0, MAX_STRING_LENGTH);
    }
};

/// \brief Read arguments from command line.
///
/// This function reads arguments from command line and stores the results
/// into \p commandLineConfig .  Prints usage if argument processing fails
/// for any reason.
///
/// \param argc               Number of arguments to the command line
/// \param argv               Array of arguments to the command line
/// \param commandLineConfig  The structure in which to store (most of) the results
/// \param simProps           Used to set simProps in kernel
/// \param product_info       The product info printed if \c -version is an argument
/// \param onlyVerifyLicense  Used to set onlyVerifyLicense in kernel
/// \param onlyPrintLibraries Used to set onlyPrintLibraries in kernel
/// \param onlyForGUI         Used to set onlyForGUI in kernel
///
/// \retval FALSE  if execution should stop due to errors in the processed arguments
/// \retval TRUE   otherwise
BOOL PARTITION_ParseArgv(
    int argc,
    char **argv,
    CommandLineConfig& commandLineConfig,
    SimulationProperties &simProps,
    const std::string &product_info,
    BOOL &onlyVerifyLicense,
    BOOL &onlyPrintLibraries,
    BOOL &onlyForGUI,
    ProductType productType);

/* FUNCTION     PARTITION_RunStatsDbRegression
 * PURPOSE      Run database regression if DB is enabled
 *
 * Parameters
 *    prefix: char*: The name of the experiment
 */
void PARTITION_RunStatsDbRegression(char* prefix);

bool PARTITION_IsMilitaryLibraryEnabled();


/// \brief Keeps track of virtual interfaces.
/// This information is used when processing HITL commands.
/// \param node Pointer to the node
/// \param interfaceIndex index of the virtual interface
void PARTITION_DeclareVirtualInterface(Node *node, int interfaceIndex);

/// \brief Identifies virtual interfaces.
/// This information is used when processing HITL commands.
/// \param node Pointer to the node
/// \param interfaceIndex index of the virtual interface
/// \return true if the interface is virtual
bool PARTITION_IsVirtualInterface(Node *node, int interfaceIndex);

#if defined(ELEKTRAFIED)
MFMSingleton& mfmc();
void PARALLEL_ConstructMachine(Elektra::Mid, int);
void PARALLEL_StartMachine();
void PARALLEL_StopMachine();
void PARALLEL_DestructMachine();
void PARALLEL_WaitBarrier(BarrierId);
void PARALLEL_WaitBarrier(BarrierDefinition&&);
#endif

#ifdef EXATA
BOOL PARTITION_ReplayForwardFromNetworkLayer(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL skipCheck);

BOOL PARTITION_ReplayForwardFromNetworkLayer(
    Node* node,
    int interfaceIndex,
    Message* msg);

BOOL PARTITION_GetReplayMode(Node* node);

void PARTITION_RecordHandleIPv6SniffedPacket(
    Address interfaceAddress,
    clocktype delay,
    Address srcAddr,
    Address destAddr,
    TosType tos,
    unsigned char protocol,
    unsigned hlim,
    char* payload,
    Int32 payloadSize,
    EXTERNAL_Interface* iface);

void PARTITION_RecordHandleSniffedPacket(
    NodeAddress interfaceAddress,
    clocktype delay,
    NodeAddress srcAddr,
    NodeAddress destAddr,
    unsigned short identification,
    BOOL dontFragment,
    BOOL moreFragments,
    unsigned short fragmentOffset,
    TosType tos,
    unsigned char protocol,
    unsigned int ttl,
    char *payload,
    int payloadSize,
    NodeAddress nextHopAddr,
    int ipHeaderLength,
    char *ipOptions,
    EXTERNAL_Interface* iface);
#endif

#endif /* _PARTITION_H_ */

