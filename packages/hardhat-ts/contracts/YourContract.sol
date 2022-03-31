pragma solidity >=0.8.0 <0.9.0;

import "hardhat/console.sol";
// SPDX-License-Identifier: GPL-3.0
pragma experimental ABIEncoderV2;
import "@openzeppelin/contracts/access/AccessControl.sol";

/*###############################################################
###                                                           ###
###                       QMIND 2021                          ###
###               BC-SUPPLYCHAIN : ETHEREUM                   ###
###               CONTRACT       : CHAIN                      ###
###                                                           ###
###   This contract develops a database of transactions       ###
###   - Create parts to assemble cars, track their origin     ###
###   =====================================================    ###
###   Authors: Bhavan Suthakaran                              ###
###            Max Kang                                       ###
###            Mit Patel                                      ###
###            Mitchell Sabbadini                             ###
###            Andrew Sutcliffe                               ###
###                                                           ###
##############################################################**/

contract YourContract is AccessControl {
  //Define Roles
  bytes32 public constant OWNR_ROLE = keccak256("OWNER ROLE");
  bytes32 public constant FAC_ROLE = keccak256("FACTORY ROLE");
  bytes32 public constant RAW_ROLE = keccak256("RAW SUPPLIER ROLE");
  bytes32 public constant MID_ROLE = keccak256("MID SUPPLIER ROLE");

  //Constructor
  constructor() {
    // Setup permissions for the contract
    _owner = msg.sender;
    _setupRole(DEFAULT_ADMIN_ROLE, msg.sender); // Sets up the Default Admin role and grants it to the deployer
    _setRoleAdmin(OWNR_ROLE, DEFAULT_ADMIN_ROLE); // Sets the role granted to the deployer as the admin role
    _grantRole(OWNR_ROLE, msg.sender); // Grhants this new role to the deployer

    // assign costs to modular parts
    _costs[4] = 3;
    _costs[5] = 2;
    _costs[6] = 2;
    _costs[7] = 4;
  }

  //Define Events
  event RawSupplierAdded(address indexed account);
  event RawSupplierRemoved(address indexed account);
  event MidSupplierAdded(address indexed account);
  event MidSupplierRemoved(address indexed account);
  event FactoryAdded(address indexed account);
  event FactoryRemoved(address indexed account);
  event ShippingFailure(string _message, uint256 _timeStamp);
  event ShippingSuccess(string _message, uint256 _trackingNo, uint256 _timeStamp, address _sender);

  //Define Structs and Local Variables
  uint8 private _sku_count = 0;
  address public _owner;

  //ItemModular
  struct itemModular {
    uint256 sku; // SKU is item ID
    uint256 upc; // UPC is item type, ex 2 = rubber, 3 = wood
    uint256 originProduceDate; // Date item produced in factory
    string itemName; // English description of part
    uint256 productPrice; // Product Price
    address manufacID; // Ethereum address of the Distributor
    uint256[] components; // store SKU's of parts
  }

  //ItemAtomic
  struct itemAtomic {
    uint256 sku; // SKU is item ID
    uint256 upc; // UPC is item type, ex 2 = rubber, 3 = wood
    uint256 originProduceDate; // Date item produced in factory
    string itemName; // English description of part
    uint256 productPrice; // Product Price
    address manufacID; // Ethereum address of the Distributor
  }

  //Shipments
  struct shipment {
    uint256 upc; // Item(s) identifier
    uint256 quantity; // Number of items in the shipment
    uint256 timeStamp; // Will be used to define when shipment is sent
    address payable sender; // ETH Address of the sender
    uint256 contractLeadTime; // Predetermined allowable timeframe for delivery
  }
  //Stakeholder
  struct stakeholder {
    address _id; // ETH address of the stakeholder
    string _name; // name of this stakeholder
    string _location; // location
    uint8 _upc; // what does this manufacturer make?
  }

  //Define Mappings
  mapping(uint256 => shipment) public _shipments; // tracking No. -> shipment
  mapping(address => bytes32) public _parties; // Stores ranks for involved parties
  mapping(address => uint256) public _accounts; // list of accounts
  mapping(address => stakeholder) public _stakeholders; // List of stakeholders
  mapping(uint256 => itemModular) public _products; // list of completed products
  mapping(uint256 => uint256) public _costs; // keep track of costs of modular parts

  // Hold completed parts and resources
  itemAtomic[] public metalQ;
  itemAtomic[] public rubberQ;
  itemAtomic[] public plasticQ;
  itemModular[] public carQ;
  itemModular[] public wheelQ;
  itemModular[] public engineQ;
  itemModular[] public chassisQ;
  itemModular[] public interiorQ;

  //Define Modifiers
  //Used to control authority
  modifier onlyRaw() {
    require(hasRole(RAW_ROLE, msg.sender));
    _;
  }
  modifier onlyMid() {
    require(hasRole(MID_ROLE, msg.sender));
    _;
  }
  modifier onlyFac() {
    require(hasRole(FAC_ROLE, msg.sender));
    _;
  }
  modifier onlyOwner() {
    require(hasRole(OWNR_ROLE, msg.sender));
    _;
  }
  modifier onlyStakeholder() {
    require(hasRole(FAC_ROLE, msg.sender) || hasRole(MID_ROLE, msg.sender) || hasRole(RAW_ROLE, msg.sender) || hasRole(OWNR_ROLE, msg.sender));
    _;
  }

  //Functions:
  //Add a role/Remove a role – modular
  function addStakeholder(
    address addy,
    uint8 upc,
    string calldata name,
    string calldata loc,
    string calldata roleStr
  ) public onlyOwner {
    // Link manufacturer credentials using the mappings/structs created above
    stakeholder memory x = stakeholder(addy, name, loc, upc); // Create a new instance of the struct
    _stakeholders[addy] = x; // Add this to the list of stakeholders

    bytes32 role = keccak256(abi.encodePacked(roleStr));
    if (role == RAW_ROLE) {
      emit RawSupplierAdded(addy);
      _parties[addy] = RAW_ROLE;
      _grantRole(RAW_ROLE, addy);
    }
    if (role == MID_ROLE) {
      emit MidSupplierAdded(addy);
      _parties[addy] = MID_ROLE;
      _grantRole(MID_ROLE, addy);
    }
    if (role == FAC_ROLE) {
      emit FactoryAdded(addy);
      _parties[addy] = FAC_ROLE;
      _grantRole(FAC_ROLE, addy);
    }
  }

  function removeStakeholder(address x, string calldata roleStr) public onlyOwner {
    bytes32 ROLE = keccak256(abi.encodePacked(roleStr));
    if (hasRole(ROLE, x)) {
      _revokeRole(ROLE, x);
    }
    delete _stakeholders[x];
    delete _parties[x];
  }

  function checkStakeholder(address s) public view returns (stakeholder memory) {
    // This function will let any user to pull out stakeholder details using their address
    return _stakeholders[s];
  }

  //Get Price, Make Product
  function getPrice(uint256 sku) public view returns (uint256 price) {
    // Fetch the price of a product given a SKU
    return _products[sku].productPrice;
  }

  //Function to send and receive shipments
  function sendShipment(
    uint256 _trackingNo,
    uint256 _upc,
    uint256 _quantity,
    uint256 _leadTime
  ) public payable onlyStakeholder returns (bool success) {
    // Function for manufacturer to send a shipment of _quanity number of _upc
    // Fill out shipment struct for a given tracking number
    shipment memory newShipment = shipment({
      upc: _upc, // Item(s) identifier
      quantity: _quantity, // Number of items in the shipment
      timeStamp: block.timestamp, // Will be used to define when shipment is sent
      sender: payable(msg.sender), // ETH Address of the sender
      contractLeadTime: _leadTime // Predetermined allowable timeframe for delivery
    });

    _shipments[_trackingNo] = newShipment;

    // emit successful event
    emit ShippingSuccess("Items Shipped", _trackingNo, block.timestamp, msg.sender);
    return true;
  }

  function receiveShipment(
    uint256 trackingNo,
    uint256 upc,
    uint256 quantity
  ) public payable onlyStakeholder returns (bool success) {
    /*
            Checking for the following conditions
                - Item [Tracking Number] and Quantity match the details from the sender
                - Once the above conditions are met, check if the location, shipping time and lead time (delay between when an order is placed and processed)
                 match and call the sendFunds function
                - The above conditions can be applied as nested if statements and have events triggered within as each condition is met
        */
    //checking that the item and quantity received match the item and quantity shipped
    if (_shipments[trackingNo].upc == upc && _shipments[trackingNo].quantity == quantity) {
      emit ShippingSuccess("Items received", trackingNo, block.timestamp, msg.sender);
      if (block.timestamp <= _shipments[trackingNo].timeStamp + _shipments[trackingNo].contractLeadTime) {
        //checks have been passed, send tokens from the assmbler to the manufacturer
        //uint price = s.getPrice(upc);
        //uint transferAmt = quantity * price;
        //sendFunds(_shipments[trackingNo].sender, transferAmt);
      } else {
        emit ShippingFailure("Payment not triggered as time criteria weas not met", block.timestamp);
      }
      return true;
    } else {
      emit ShippingFailure("Issue in item/quantity", block.timestamp);
      return false;
    }
  }

  function findShipment(uint8 trackingNo) public view returns (shipment memory) {
    return _shipments[trackingNo];
  }

  //Functions with modifiers to produce and ship/receive modular parts
  function produceModularPart(
    string calldata name,
    uint256 productCode,
    uint256 price
  ) public onlyMid {
    // We will define 3 types of modular products
    /**
        1) Chassis - cost = 3 metal               : UPC 4
        2) Motor && drivetrain - cost 2 metal     : UPC 5
        3) Interior - cost 2 plastic              : UPC 6
        4) Wheels - cost 4 rubber                 : UPC 7
        */

    require(productCode <= 7 && productCode >= 4);
    // get the components of the modular part
    uint256[] memory comp = new uint256[](5);

    if (productCode != 6) {
      if (productCode == 4) {
        // Chassis
        require(metalQ.length >= _costs[4]);
        for (uint256 i = 0; i < _costs[4]; i++) {
          uint256 s = metalQ[metalQ.length - 1].sku;
          comp[i] = s;
          metalQ.pop();
        }
      } else if (productCode == 5) {
        // Motor and Transmission
        require(metalQ.length >= _costs[5]);
        for (uint256 i = 0; i < _costs[5]; i++) {
          uint256 s = metalQ[metalQ.length - 1].sku;
          comp[i] = s;
          metalQ.pop();
        }
      } else {
        // Wheels
        require(rubberQ.length >= _costs[7]);
        for (uint256 i = 0; i < _costs[7]; i++) {
          uint256 s = rubberQ[rubberQ.length - 1].sku;
          comp[i] = s;
          rubberQ.pop();
        }
      }
    } else {
      // Interior
      require(metalQ.length >= _costs[6]);
      for (uint256 i = 0; i < _costs[6]; i++) {
        uint256 s = plasticQ[plasticQ.length - 1].sku;
        comp[i] = s;
        plasticQ.pop();
      }
    }

    itemModular memory n = itemModular({
      sku: _sku_count,
      upc: productCode,
      originProduceDate: block.timestamp,
      itemName: name,
      productPrice: price,
      manufacID: msg.sender,
      components: comp
    });

    // put into respective queue
    if (productCode == 4) {
      chassisQ.push(n);
    } else if (productCode == 5) {
      engineQ.push(n);
    } else if (productCode == 6) {
      interiorQ.push(n);
    } else {
      wheelQ.push(n);
    }
    _sku_count++;
  }

  // Create an atomic part
  function produceAtomicPart(
    string calldata name,
    uint256 productCode,
    uint256 price,
    uint256 quantity
  ) public onlyRaw {
    // product code is item type:
    //      1 - metal
    //      2 - plastic
    //      3 - rubber

    for (uint256 i = 0; i < quantity; i++) {
      // push quantity times to array
      itemAtomic memory n = itemAtomic({
        sku: _sku_count,
        upc: productCode,
        originProduceDate: block.timestamp,
        itemName: name,
        productPrice: price,
        manufacID: msg.sender
      });
      // check type of productCode, put into appropriate array
      // atomicQ.push(n);

      if (productCode == 1) {
        metalQ.push(n);
      } else if (productCode == 2) {
        plasticQ.push(n);
      } else {
        rubberQ.push(n);
      }
      _sku_count++;
    }
  }

  function produceCar(
    string calldata name,
    uint256 productCode,
    uint256 price
  ) public onlyFac {
    // create a car item
    require(interiorQ.length >= 1 && chassisQ.length >= 1 && engineQ.length >= 1 && wheelQ.length >= 1);
    // get car components
    uint256 x = interiorQ[interiorQ.length - 1].sku;
    uint256 y = chassisQ[chassisQ.length - 1].sku;
    uint256 z = engineQ[engineQ.length - 1].sku;
    uint256 w = wheelQ[wheelQ.length - 1].sku;
    uint256[] memory comp = new uint256[](4);
    interiorQ.pop();
    chassisQ.pop();
    engineQ.pop();
    wheelQ.pop();
    comp[0] = x;
    comp[1] = y;
    comp[2] = z;
    comp[3] = w;
    // make the car
    itemModular memory c = itemModular({
      sku: _sku_count,
      upc: productCode,
      originProduceDate: block.timestamp,
      itemName: name,
      productPrice: price,
      manufacID: msg.sender,
      components: comp
    });
    _sku_count++;
    carQ.push(c);
  }
}
